# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Enumerators for Automotive Scanner
# scapy.contrib.status = loads

from collections import defaultdict, namedtuple

from scapy.error import Scapy_Exception
from scapy.utils import make_lined_table
from scapy.modules import six


class Graph:
    def __init__(self):
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.weights has all the weights between two nodes,
        with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)
        self.weights = {}

    def add_edge(self, from_node, to_node, weight=1):
        # Note: assumes edges are bi-directional
        self.edges[from_node].append(to_node)
        self.edges[to_node].append(from_node)
        self.weights[(from_node, to_node)] = weight
        self.weights[(to_node, from_node)] = weight

    @staticmethod
    def dijsktra(graph, initial, end):
        # shortest paths is a dict of nodes
        # whose value is a tuple of (previous node, weight)
        shortest_paths = {initial: (None, 0)}
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = \
                    graph.weights[(current_node, next_node)] + \
                    weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {node: shortest_paths[node] for node in
                                 shortest_paths if node not in visited}
            if not next_destinations:
                return None
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        path = []
        while current_node is not None:
            path.append(current_node)
            next_node = shortest_paths[current_node][0]
            current_node = next_node
        # Reverse path
        path = path[::-1]
        return path


class Enumerator(object):
    """ Base class for Enumerators

    Args:
        sock: socket where enumeration takes place
    """
    description = "About my results"
    negative_response_blacklist = []
    ScanResult = namedtuple("ScanResult", "session req resp")

    def __init__(self, sock):
        self.sock = sock
        self.results = list()

    def scan(self, session, requests, **kwargs):
        _tm = kwargs.pop("timeout", 0.5)
        _verb = kwargs.pop("verbose", False)
        _exit_if_service_not_supported = \
            kwargs.pop("exit_if_service_not_supported", False)
        for req in requests:
            res = self.sock.sr1(req, timeout=_tm, verbose=_verb, **kwargs)
            if res and res.service == 0x11 and _exit_if_service_not_supported:
                print("Exit scan because negative response "
                      "serviceNotSupported received!")
                return
            self.results.append(Enumerator.ScanResult(session, req, res))

    @property
    def filtered_results(self):
        return [r for r in self.results if r.resp is not None]

    def show_negative_response_details(self):
        raise NotImplementedError("This needs a protocol specific "
                                  "implementation")

    def show(self, filtered=True):
        print("\r\n\r\n" + "=" * (len(self.description) + 10))
        print(" " * 5 + self.description)
        print("-" * (len(self.description) + 10))

        print("%d requests were sent, %d answered, %d unanswered" %
              (len(self.results),
               len([r for r in self.results if r.resp is not None]),
               len([r for r in self.results if r.resp is None])))

        nrs = [r.resp for r in self.results if r.resp is not None and
               r.resp.service == 0x7f]
        print("%d negative responses were received" % len(nrs))

        self.show_negative_response_details()

        print("The following negative response codes are blacklisted: %s" %
              self.negative_response_blacklist)

        data = self.results if not filtered else self.filtered_results
        make_lined_table(data, self.get_table_entry)

    @staticmethod
    def get_table_entry(tup):
        raise NotImplementedError()

    @staticmethod
    def get_session_string(session):
        raise NotImplementedError()

    @staticmethod
    def get_label(response,
                  positive_case="PR: PositiveResponse",
                  negative_case="NR: NegativeResponse",):
        if response is None:
            label = "Timeout"
        elif response.service == 0x7f:
            label = negative_case
        else:
            if isinstance(positive_case, six.string_types):
                label = positive_case
            elif callable(positive_case):
                label = positive_case()
            else:
                raise Scapy_Exception("Unsupported Type for positive_case. "
                                      "Provide a string or a function.")
        return label

    @staticmethod
    def enter_session(socket, session, reset_handler=None,
                      verbose=False, **kwargs):
        raise NotImplementedError()
