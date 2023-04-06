# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
from abc import ABC, abstractmethod

from testlib.cluster import Cluster, build_cluster


class ClusterRequirements:
    def __init__(self, edition="Enterprise", num_nodes=1, min_memsize=256,
                 num_connected=None):
        self.requirements = [Edition(edition),
                             NumNodes(num_nodes, num_connected),
                             MemSize(min_memsize)]

    def __str__(self):
        return ','.join([str(requirement) for requirement in self.requirements])

    @staticmethod
    def get_default_start_args():
        return {
                # Don't rename first node when second node joins the cluster,
                # as this makes node removal / addition testing more complicated
                'dont_rename': True,
                # Wait until nodes are up before cluster_run_lib returns
                'wait_for_start': True,
                # Without this we would have cluster outputs overlapping test
                # output
                'nooutput': True
        }

    @staticmethod
    def get_default_connect_args():
        return {}

    def create_cluster(self, auth, start_index, tmp_cluster_dir):
        start_args = {'start_index': start_index,
                      'root_dir': f"{tmp_cluster_dir}-{start_index}"}
        start_args.update(self.get_default_start_args())
        for requirement in self.requirements:
            start_args.update(requirement.start_args)

        connect_args = {'start_index': start_index}
        connect_args.update(self.get_default_connect_args())
        for requirement in self.requirements:
            connect_args.update(requirement.connect_args)

        return build_cluster(auth=auth, start_args=start_args,
                             connect_args=connect_args)

    def is_met(self, cluster):
        for requirement in self.requirements:
            if not requirement.is_met(cluster):
                return False
        return True

    # Determines whether this set of requirements will be satisfiable with a
    # cluster satisfying some 'other' ClusterRequirements
    def satisfied_by(self, other):
        for requirement in self.requirements:
            if not (any(requirement == other_requirement
                        for other_requirement in other.requirements)):
                return False
        return True


class Requirement(ABC):
    def __init__(self, name, value):
        # In order to provide a string representation of the requirement, we
        # need to be provided with a name and value
        self._name = name
        self._value = value

        # Override to make a requirement that depends on arguments for
        # cluster_run_lib.start()
        self.start_args = {}
        # Override to make a requirement that depends on arguments for
        # cluster_run_lib.connect()
        self.connect_args = {}

    def __str__(self):
        return f"{self._name}={self._value}"

    def __eq__(self, other):
        return str(self) == str(other)

    @abstractmethod
    def is_met(self, cluster):
        raise NotImplementedError()


class Edition(Requirement):
    editions = ["Community", "Enterprise", "Serverless"]

    def __init__(self, edition):
        super().__init__("edition", edition)
        if edition not in Edition.editions:
            raise ValueError(f"Edition must be in {Edition.editions}")

        self.edition = edition

        if self.edition == "Community":
            self.start_args = {'force_community': True,
                               'run_serverless': False}
        elif self.edition == "Enterprise":
            self.start_args = {'force_community': False,
                               'run_serverless': False}
        elif self.edition == "Serverless":
            self.start_args = {'force_community': False,
                               'run_serverless': True}

    def is_met(self, cluster: Cluster):
        if self.edition == "Community":
            return not cluster.is_enterprise and not cluster.is_serverless
        elif self.edition == "Enterprise":
            return cluster.is_enterprise and not cluster.is_serverless
        elif self.edition == "Serverless":
            return cluster.is_enterprise and cluster.is_serverless


class NumNodes(Requirement):
    def __init__(self, num_nodes, num_connected):
        super().__init__("num_nodes", num_nodes)
        if num_nodes < 1:
            raise ValueError(f"num_nodes must be a positive integer")
        self.num_nodes = num_nodes
        self.start_args = {'num_nodes': self.num_nodes}
        self.connect_args = {'num_nodes': self.num_nodes}
        # If num_connected is None then we require all nodes to be connected,
        # so we will rebalance if there is more than 1 node (unless the testset
        # requires otherwise)
        if num_connected is None:
            if num_nodes > 1:
                self.connect_args.update({'do_rebalance': True,
                                          'do_wait_for_rebalance': True})
            else:
                self.connect_args.update({'do_rebalance': False})
        else:
            if num_connected < 1:
                raise ValueError("num_connected must be at least 1")
            self.connect_args.update({'num_nodes': num_connected})
            if num_connected > 1:
                self.connect_args.update({'do_rebalance': True,
                                          'do_wait_for_rebalance': True})
            else:
                self.connect_args.update({'do_rebalance': False})

        self.num_connected = num_connected

    def is_met(self, cluster):
        return (len(cluster.nodes) >= self.num_nodes and
                (self.num_connected is None and
                 len(cluster.connected_nodes) == len(cluster.nodes)) or
                (self.num_connected is not None and
                 len(cluster.connected_nodes) >= self.num_connected))


class MemSize(Requirement):
    def __init__(self, memsize):
        super().__init__("memsize", memsize)
        if memsize < 256:
            raise ValueError(f"memsize must be a positive integer >= 256")
        self.memsize = memsize
        self.connect_args = {'memsize': self.memsize}

    def is_met(self, cluster):
        return cluster.memsize >= self.memsize
