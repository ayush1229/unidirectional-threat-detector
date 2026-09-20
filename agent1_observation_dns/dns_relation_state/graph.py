"""Observed query relationships only; never infer unseen answer/IP edges."""
from collections import OrderedDict
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.state_observation.dns import parent_domain


class DNSGraph:
    def __init__(self, config: Settings):
        self.config = config
        self.nodes: OrderedDict[tuple, int] = OrderedDict()
        self.edges: OrderedDict[tuple, int] = OrderedDict()

    def expire(self, ns):
        cutoff = ns - self.config.graph_ttl_s * 1e9
        self.nodes = OrderedDict((k, t) for k, t in self.nodes.items() if t > cutoff)
        self.edges = OrderedDict((k, t) for k, t in self.edges.items()
                                 if t > cutoff and k[0] in self.nodes and k[1] in self.nodes)

    def update(self, packet, record):
        self.expire(packet.timestamp_ns)
        client = ("client", packet.destination if record.response else packet.source)
        resolver = ("resolver", packet.source if record.response else packet.destination)
        domain = ("domain", parent_domain(record.name))
        for node in (client, resolver, domain):
            self.nodes[node] = packet.timestamp_ns
            self.nodes.move_to_end(node)
        for edge in ((client, domain), (domain, resolver)):
            self.edges[edge] = packet.timestamp_ns
            self.edges.move_to_end(edge)
        while len(self.nodes) > self.config.max_graph_nodes:
            self.nodes.popitem(last=False)
        self.edges = OrderedDict((e, t) for e, t in self.edges.items() if e[0] in self.nodes and e[1] in self.nodes)
        while len(self.edges) > self.config.max_graph_edges:
            self.edges.popitem(last=False)

    def structural_snapshot(self):
        """Anonymous node type/degree representation; IP/domain identities excluded."""
        nodes = list(self.nodes)
        indexes = {n: i for i, n in enumerate(nodes)}
        edges = [[indexes[a], indexes[b]] for a, b in self.edges]
        degrees = [sum(i in edge for edge in edges) for i in range(len(nodes))]
        return {"nodes": [[float(n[0] == t) for t in ("client", "domain", "resolver")] + [degrees[i]]
                          for i, n in enumerate(nodes)], "edges": edges,
                "sufficient": len(edges) >= self.config.graph_min_edges}
