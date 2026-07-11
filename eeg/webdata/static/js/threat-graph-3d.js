/**
 * Optional 3D vulnerability relationship graph — loaded separately from dashboard charts.
 */
(function () {
    'use strict';

    var graph3d = null;
    var graphRawData = null;
    var graphScriptsLoaded = false;
    var graphShowLabels = true;
    var graphActiveGroups = null;
    var graphSelectedId = null;

    var GRAPH_GROUP_COLORS = {
        hub: '#e6edf3',
        severity: '#da3633',
        bucket: '#58a6ff',
        project: '#3fb950',
        directory: '#768390',
        file: '#d29922',
        module: '#56d4dd',
        symbol: '#bc8cff',
        rule: '#a371f7',
        category: '#79c0ff',
        cwe: '#ff7b72',
        owasp: '#ffa657',
        pattern: '#f0883e',
        finding: '#8b949e',
        agent: '#3fb950',
        model: '#58a6ff',
        tool: '#d29922',
        mcp: '#a371f7',
        surface: '#79c0ff',
        detection: '#f85149',
        session: '#768390'
    };

    var GRAPH_LINK_COLORS = {
        file: 'rgba(210, 153, 34, 0.65)',
        rule: 'rgba(163, 113, 247, 0.55)',
        bucket: 'rgba(88, 166, 255, 0.55)',
        category: 'rgba(121, 192, 255, 0.45)',
        project: 'rgba(63, 185, 80, 0.5)',
        directory: 'rgba(118, 131, 144, 0.45)',
        severity: 'rgba(218, 54, 51, 0.4)',
        cwe: 'rgba(255, 123, 114, 0.45)',
        owasp: 'rgba(255, 166, 87, 0.45)',
        semantic: 'rgba(86, 212, 221, 0.55)',
        defines: 'rgba(188, 140, 255, 0.45)',
        imports: 'rgba(86, 212, 221, 0.35)',
        same_line: 'rgba(240, 136, 62, 0.5)',
        snippet_match: 'rgba(240, 136, 62, 0.4)',
        fp_cluster: 'rgba(63, 185, 80, 0.35)',
        pattern: 'rgba(240, 136, 62, 0.45)',
        same_rule: 'rgba(163, 113, 247, 0.35)',
        'co-occur': 'rgba(139, 148, 158, 0.25)',
        path: 'rgba(63, 185, 80, 0.3)',
        contains: 'rgba(230, 237, 243, 0.35)',
        invokes: 'rgba(210, 153, 34, 0.7)',
        uses: 'rgba(88, 166, 255, 0.55)',
        calls: 'rgba(210, 153, 34, 0.6)',
        mcp: 'rgba(163, 113, 247, 0.65)',
        emits: 'rgba(121, 192, 255, 0.5)',
        detection: 'rgba(248, 81, 73, 0.55)',
        session: 'rgba(118, 131, 144, 0.4)'
    };

    function graphUrl() {
        var page = document.getElementById('threat-graph-page');
        if (page && page.getAttribute('data-graph-url')) {
            return page.getAttribute('data-graph-url');
        }
        return '/partials/threat-graph/?limit=150';
    }

    function loadGraphScript(src) {
        return new Promise(function (resolve, reject) {
            if (document.querySelector('script[src="' + src + '"]')) {
                resolve();
                return;
            }
            var s = document.createElement('script');
            s.src = src;
            s.onload = resolve;
            s.onerror = reject;
            document.head.appendChild(s);
        });
    }

    function graphNodeColor(node) {
        if (node.group === 'finding') {
            var fp = node.fp_score || 0;
            if (fp >= 70) return '#f0883e';
            if (fp >= 55) return '#d29922';
            var sev = node.severity || 'medium';
            if (sev === 'critical') return '#da3633';
            if (sev === 'high') return '#f85149';
            if (sev === 'medium') return '#d29922';
            if (sev === 'low') return '#3fb950';
        }
        if (node.group === 'severity' && node.severity) {
            return graphNodeColor({ group: 'finding', severity: node.severity });
        }
        return GRAPH_GROUP_COLORS[node.group] || '#8b949e';
    }

    function graphNodeRadius(node) {
        return Math.pow(node.val || 1, 0.45) * 2.2;
    }

    function graphLinkColor(link) {
        return GRAPH_LINK_COLORS[link.type] || 'rgba(139, 148, 158, 0.3)';
    }

    function graphLinkWidth(link) {
        return (link.strength || 0.5) * 1.4;
    }

    function graphNodeLabel(node) {
        var lines = [node.name || node.label || node.id || 'node'];
        if (node.path) lines.push(node.path);
        if (node.group === 'finding' && node.file_path) {
            lines.push(node.file_path + (node.line_number ? ':' + node.line_number : ''));
        }
        if (node.bucket_label) lines.push(node.bucket_label);
        if (node.rule_id) lines.push(node.rule_id);
        if (node.subtitle) lines.push(node.subtitle);
        if (node.agent_key) lines.push('key: ' + node.agent_key);
        if (node.control_status) lines.push('status: ' + node.control_status);
        return lines.join('\n');
    }

    function setInspectorVisible(show) {
        var workspace = document.getElementById('threat-graph-workspace');
        if (workspace) workspace.classList.toggle('threat-graph-workspace--detail', !!show);
    }

    function renderGraphInspector(node, neighbors) {
        var titleEl = document.getElementById('threat-graph-inspector-title');
        var typeEl = document.getElementById('threat-graph-inspector-type');
        var bodyEl = document.getElementById('threat-graph-inspector-body');
        if (!bodyEl) return;

        if (!node) {
            setInspectorVisible(false);
            if (titleEl) titleEl.textContent = '';
            if (typeEl) typeEl.textContent = '';
            bodyEl.innerHTML = '';
            return;
        }

        setInspectorVisible(true);
        if (titleEl) titleEl.textContent = node.name;
        if (typeEl) typeEl.textContent = (node.group || 'node').replace(/_/g, ' ');

        var html = '';
        if (node.group === 'finding') {
            html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Severity</div><div class="threat-graph-inspector__value"><span class="severity-badge severity-' + (node.severity || 'medium') + '">' + (node.severity || '') + '</span></div></div>';
            if (node.file_path) {
                html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Location</div><div class="threat-graph-inspector__value"><code>' + node.file_path + (node.line_number ? ':' + node.line_number : '') + '</code></div></div>';
            }
            if (node.rule_id) html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Rule</div><div class="threat-graph-inspector__value"><code>' + node.rule_id + '</code></div></div>';
            if (node.bucket_label) html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Threat category</div><div class="threat-graph-inspector__value">' + node.bucket_label + '</div></div>';
            if (node.cwe) html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">CWE</div><div class="threat-graph-inspector__value">CWE-' + node.cwe + '</div></div>';
            if (node.owasp_llm) html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">OWASP LLM</div><div class="threat-graph-inspector__value">' + node.owasp_llm + '</div></div>';
            if (node.fp_score != null) {
                html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">FP risk</div><div class="threat-graph-inspector__value">' + node.fp_score + '/100';
                if (node.fp_signals && node.fp_signals.length) {
                    html += ' <span class="muted">(' + node.fp_signals.join(', ') + ')</span>';
                }
                html += '</div></div>';
            }
            if (node.snippet) html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Snippet</div><pre class="threat-graph-inspector__snippet">' + node.snippet.replace(/</g, '&lt;') + '</pre></div>';
            html += '<div class="threat-graph-inspector__row"><a href="/findings/?highlight=' + encodeURIComponent(node.id.replace('finding:', '')) + '" class="btn btn-secondary" style="font-size:0.72rem;">Open finding</a></div>';
        } else if (node.path) {
            html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Path</div><div class="threat-graph-inspector__value"><code>' + node.path + '</code></div></div>';
            html += '<div class="threat-graph-inspector__row"><a href="/findings/?q=' + encodeURIComponent(node.path) + '" class="btn btn-secondary" style="font-size:0.72rem;">Search findings</a></div>';
        } else if (node.count) {
            html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Findings</div><div class="threat-graph-inspector__value">' + node.count + '</div></div>';
        } else if (node.finding_count) {
            html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Findings in file</div><div class="threat-graph-inspector__value">' + node.finding_count + '</div></div>';
        }

        if (neighbors && neighbors.length) {
            html += '<div class="threat-graph-inspector__row"><div class="threat-graph-inspector__label">Connected (' + neighbors.length + ')</div><ul class="threat-graph-inspector__links">';
            neighbors.slice(0, 12).forEach(function (n) {
                html += '<li><strong>' + n.group + '</strong> · ' + n.name + '</li>';
            });
            if (neighbors.length > 12) html += '<li class="muted">+' + (neighbors.length - 12) + ' more</li>';
            html += '</ul></div>';
        }
        bodyEl.innerHTML = html;
    }

    function buildGraphFilters(groups) {
        var wrap = document.getElementById('threat-graph-filters');
        if (!wrap || !groups) return;
        wrap.innerHTML = '';
        graphActiveGroups = new Set(groups);
        groups.forEach(function (g) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'threat-graph-filter threat-graph-filter--on';
            btn.dataset.group = g;
            btn.textContent = g;
            btn.addEventListener('click', function () {
                if (graphActiveGroups.has(g)) {
                    graphActiveGroups.delete(g);
                    btn.classList.remove('threat-graph-filter--on');
                } else {
                    graphActiveGroups.add(g);
                    btn.classList.add('threat-graph-filter--on');
                }
                if (graph3d) graph3d.nodeVisibility(function (n) { return graphActiveGroups.has(n.group); });
            });
            wrap.appendChild(btn);
        });
    }

    function graphNodeThreeObject(node) {
        if (typeof THREE === 'undefined') return false;
        var group = new THREE.Group();
        var radius = graphNodeRadius(node);
        var color = graphNodeColor(node);
        var geom = new THREE.SphereGeometry(radius, 20, 20);
        var mat = new THREE.MeshPhongMaterial({
            color: color,
            emissive: color,
            emissiveIntensity: node.group === 'finding' ? 0.45 : (node.group === 'hub' ? 0.35 : 0.18),
            transparent: true,
            opacity: graphSelectedId && graphSelectedId !== node.id ? 0.35 : 0.92
        });
        group.add(new THREE.Mesh(geom, mat));

        if (graphShowLabels && (
            node.group === 'finding' ||
            node.group === 'file' ||
            node.group === 'bucket' ||
            node.group === 'hub' ||
            node.group === 'agent' ||
            node.group === 'tool' ||
            node.group === 'mcp' ||
            node.group === 'model' ||
            node.val >= 4
        )) {
            if (typeof SpriteText !== 'undefined') {
                var labelText = (node.name || node.label || node.id || '');
                var sprite = new SpriteText(labelText.length > 28 ? labelText.slice(0, 26) + '…' : labelText);
                sprite.color = '#e6edf3';
                sprite.textHeight = node.group === 'hub' ? 5.5 : (node.group === 'finding' || node.group === 'agent' ? 3.2 : 2.8);
                sprite.backgroundColor = 'rgba(13,17,23,0.75)';
                sprite.padding = 2;
                sprite.borderRadius = 2;
                sprite.position.y = radius + sprite.textHeight * 0.55;
                group.add(sprite);
            }
        }
        return group;
    }

    function highlightGraphNode(node) {
        graphSelectedId = node ? node.id : null;
        if (!graph3d || !graphRawData) {
            renderGraphInspector(node, []);
            return;
        }

        var neighborIds = new Set();
        if (node) {
            neighborIds.add(node.id);
            graphRawData.links.forEach(function (l) {
                var s = typeof l.source === 'object' ? l.source.id : l.source;
                var t = typeof l.target === 'object' ? l.target.id : l.target;
                if (s === node.id) neighborIds.add(t);
                if (t === node.id) neighborIds.add(s);
            });
        }

        graph3d
            .linkWidth(function (l) {
                var s = typeof l.source === 'object' ? l.source.id : l.source;
                var t = typeof l.target === 'object' ? l.target.id : l.target;
                var onPath = node && (s === node.id || t === node.id);
                return graphLinkWidth(l) * (onPath ? 2.2 : 0.35);
            })
            .linkColor(function (l) {
                var s = typeof l.source === 'object' ? l.source.id : l.source;
                var t = typeof l.target === 'object' ? l.target.id : l.target;
                var onPath = node && (s === node.id || t === node.id);
                return onPath ? graphLinkColor(l) : 'rgba(48, 54, 61, 0.25)';
            })
            .nodeThreeObject(graphNodeThreeObject)
            .nodeThreeObjectExtend(true);

        var neighbors = [];
        if (node) {
            graphRawData.nodes.forEach(function (n) {
                if (neighborIds.has(n.id) && n.id !== node.id) neighbors.push(n);
            });
        }
        renderGraphInspector(node, neighbors);
    }

    function initThreatGraph3d(container, data) {
        if (typeof ForceGraph3D !== 'function') {
            throw new Error('ForceGraph3D not available');
        }
        graphRawData = data;
        buildGraphFilters(data.meta && data.meta.groups ? data.meta.groups : []);

        if (graph3d && graph3d._destructor) graph3d._destructor();

        graph3d = ForceGraph3D()(container)
            .width(container.clientWidth)
            .height(container.clientHeight)
            .backgroundColor('#0a0e14')
            .showNavInfo(false)
            .graphData(data)
            .nodeLabel(graphNodeLabel)
            .nodeColor(graphNodeColor)
            .nodeVal(function (n) { return Math.pow(n.val || 1, 0.5); })
            .nodeThreeObject(graphNodeThreeObject)
            .nodeThreeObjectExtend(true)
            .linkColor(graphLinkColor)
            .linkWidth(graphLinkWidth)
            .linkOpacity(0.75)
            .linkDirectionalParticles(function (l) {
                return (l.type === 'file' || l.type === 'bucket' || l.type === 'rule') ? 2 : 0;
            })
            .linkDirectionalParticleWidth(1.2)
            .linkDirectionalParticleSpeed(0.006)
            .warmupTicks(120)
            .cooldownTicks(80)
            .onNodeClick(function (node) {
                highlightGraphNode(node);
                var dist = 140;
                graph3d.cameraPosition(
                    { x: node.x + dist * 0.4, y: node.y + dist * 0.35, z: node.z + dist },
                    node,
                    1200
                );
            })
            .onBackgroundClick(function () { highlightGraphNode(null); });

        graph3d.d3Force('charge').strength(function (n) { return -18 * Math.pow(n.val || 1, 0.55); });
        graph3d.d3Force('link').distance(function (l) { return 40 + (1.2 / (l.strength || 0.5)); });

        var resetBtn = document.getElementById('threat-graph-reset-cam');
        if (resetBtn) {
            resetBtn.onclick = function () {
                graph3d.zoomToFit(600, 80);
                highlightGraphNode(null);
            };
        }
        var labelBtn = document.getElementById('threat-graph-toggle-labels');
        if (labelBtn) {
            labelBtn.onclick = function () {
                graphShowLabels = !graphShowLabels;
                labelBtn.textContent = graphShowLabels ? 'Labels' : 'Labels off';
                graph3d.nodeThreeObject(graphNodeThreeObject).nodeThreeObjectExtend(true);
            };
        }

        setTimeout(function () { graph3d.zoomToFit(800, 90); }, 400);
    }

    function destroyThreatGraph3d() {
        if (graph3d && graph3d._destructor) {
            graph3d._destructor();
            graph3d = null;
        }
        var container = document.getElementById('threat-graph-3d');
        if (container) container.innerHTML = '';
        graphRawData = null;
        graphSelectedId = null;
    }

    function loadGraphLibraries() {
        if (graphScriptsLoaded) return Promise.resolve();
        return loadGraphScript('https://unpkg.com/three@0.160.0/build/three.min.js')
            .then(function () { return loadGraphScript('https://unpkg.com/three-spritetext@1.8.2/dist/three-spritetext.min.js'); })
            .then(function () { return loadGraphScript('https://unpkg.com/3d-force-graph@1.73.3/dist/3d-force-graph.min.js'); })
            .then(function () { graphScriptsLoaded = true; });
    }

    function resizeGraphViewport() {
        var container = document.getElementById('threat-graph-3d');
        if (graph3d && container) {
            graph3d.width(container.clientWidth).height(container.clientHeight);
        }
    }

    function loadThreatGraphPage() {
        var container = document.getElementById('threat-graph-3d');
        var metaEl = document.getElementById('threat-graph-meta');
        if (!container) return;

        container.innerHTML = '<p class="muted" style="padding:2rem;text-align:center;">Building relationship graph…</p>';
        renderGraphInspector(null, []);

        loadGraphLibraries()
            .then(function () { return fetch(graphUrl(), { headers: { Accept: 'application/json' } }); })
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
                container.innerHTML = '';
                if (!data.nodes || !data.nodes.length) {
                    var emptyMsg = (data.meta && data.meta.source === 'runtime')
                        ? 'No agentic interactions yet. Send gateway traffic (with X-EEG-Agent) to populate this graph.'
                        : 'No open findings to map. Run a scan first.';
                    container.innerHTML = '<p class="muted" style="padding:2rem;text-align:center;">' + emptyMsg + '</p>';
                    if (metaEl) metaEl.textContent = data.meta && data.meta.source === 'runtime'
                        ? 'No runtime interactions yet'
                        : 'No vulnerability relationships yet';
                    return;
                }
                if (metaEl && data.meta) {
                    var m = data.meta;
                    if (m.source === 'runtime') {
                        metaEl.textContent =
                            (m.agent_count || 0) + ' agents · ' +
                            (m.tool_count || 0) + ' tools · ' +
                            (m.interaction_count || 0) + ' interactions · ' +
                            (m.blocked || 0) + ' blocked · ' +
                            m.node_count + ' nodes · ' + m.link_count + ' links';
                    } else {
                        metaEl.textContent = m.finding_count + ' findings · ' + m.file_count + ' files · ' +
                            m.node_count + ' nodes · ' + m.link_count + ' relationships';
                    }
                }
                initThreatGraph3d(container, data);
                window.requestAnimationFrame(resizeGraphViewport);
            })
            .catch(function (err) {
                container.innerHTML = '<p class="muted" style="padding:2rem;text-align:center;color:var(--accent-danger);">Could not load 3D graph.</p>';
                console.error('[threat-graph-3d]', err);
            });
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (!document.getElementById('threat-graph-page')) return;

        loadThreatGraphPage();
        window.addEventListener('resize', resizeGraphViewport);
    });
})();
