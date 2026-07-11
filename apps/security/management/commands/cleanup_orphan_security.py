"""Remove project-less security rows left over before project-scoped runtime."""

from django.core.management.base import BaseCommand

from apps.accounts.models import Organization
from apps.projects.gateway_sync import ensure_gateway_project
from apps.projects.models import Project
from apps.security.models import AITrace, SecurityFinding


class Command(BaseCommand):
    help = (
        "Attach orphan traces to gateway projects by agent_key when possible; "
        "delete remaining project-less traces/findings."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report counts without writing.",
        )

    def handle(self, *args, **options):
        dry = bool(options["dry_run"])
        attached = 0
        deleted_traces = 0
        deleted_findings = 0

        orphans = AITrace.objects.filter(project__isnull=True).iterator(chunk_size=200)
        for trace in orphans:
            meta = trace.metadata if isinstance(trace.metadata, dict) else {}
            agent_key = str(
                meta.get("agent_key") or meta.get("agent_id") or ""
            ).strip()
            if not agent_key and (trace.session_id or "").startswith("agent-"):
                agent_key = trace.session_id[len("agent-") :].strip()
            if agent_key:
                project = ensure_gateway_project(
                    trace.organization, agent_key, name=agent_key
                )
                if project and not dry:
                    AITrace.objects.filter(pk=trace.pk).update(project=project)
                attached += 1
                continue
            if not dry:
                AITrace.objects.filter(pk=trace.pk).delete()
            deleted_traces += 1

        # Any leftovers (failed attach) and null-project findings.
        leftover = AITrace.objects.filter(project__isnull=True)
        leftover_count = leftover.count()
        if leftover_count and not dry:
            deleted_traces += leftover_count
            leftover.delete()

        findings_qs = SecurityFinding.objects.filter(project__isnull=True)
        findings_count = findings_qs.count()
        if findings_count and not dry:
            findings_qs.delete()
        deleted_findings += findings_count

        # Orgs with zero projects: drop any remaining org runtime.
        for org in Organization.objects.all():
            if Project.objects.filter(organization=org).exists():
                continue
            t_qs = AITrace.objects.filter(organization=org)
            f_qs = SecurityFinding.objects.filter(organization=org)
            if not dry:
                deleted_traces += t_qs.count()
                deleted_findings += f_qs.count()
                t_qs.delete()
                f_qs.delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"attached={attached} deleted_traces={deleted_traces} "
                f"deleted_findings={deleted_findings} dry_run={dry}"
            )
        )
