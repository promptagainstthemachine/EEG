"""EEG OSS account middleware - organization context for requests."""
from django.http import HttpRequest


class OrganizationContextMiddleware:
    """
    Middleware to attach the user's organization to the request.
    
    In OSS mode, each user owns exactly one organization.
    This is simpler than the SAAS multi-tenant model.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        request.organization = None
        
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            request.organization = getattr(user, "organization", None)
        
        return self.get_response(request)
