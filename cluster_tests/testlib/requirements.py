# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
from abc import ABC, abstractmethod

import testlib
from testlib.cluster import Cluster, build_cluster
from testlib import get_succ


class ClusterRequirements:
    @testlib.no_output_decorator
    def __init__(self, edition=None, num_nodes=None, memsize=None,
                 num_connected=None, afamily=None, services=None,
                 master_password_state=None, num_vbuckets=None):

        def maybe(f, x):
            if x is None:
                return None
            return f(x)

        if num_nodes is None and num_connected is not None:
            raise ValueError("num_connected cannot be specified without "
                             "num_nodes also being specified")
        self.requirements = \
            {
                'edition': maybe(lambda x: Edition(x), edition),
                'num_nodes':
                    maybe(lambda x: NumNodes(x, num_connected), num_nodes),
                'memsize': maybe(lambda x: MemSize(x), memsize),
                'afamily': maybe(lambda x: AFamily(x), afamily),
                'services': maybe(lambda x: Services(x), services),
                'master_password_state':
                    maybe(lambda x: MasterPasswordState(x),
                          master_password_state),
                'num_vbuckets': maybe(lambda x: NumVbuckets(x), num_vbuckets)
            }

    def __str__(self):
        all_reqs = sorted(self.as_list(), key= lambda x: x.__class__.__name__)
        immutable_requirements = list(filter(lambda x: not x.can_be_met(),
                                             all_reqs))
        mutable_requirements = list(filter(lambda x: x.can_be_met(),
                                           all_reqs))
        # List the requirements with mutables last, so that compatible
        # configurations would be adjacent when ordered by string
        requirements = immutable_requirements + mutable_requirements
        return ','.join([str(req) for req in requirements])

    def __repr__(self):
        return str(self)

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
                'nooutput': True,
                'num_nodes': 1,
                # Reduce the default num vbuckets to 16 to aid with faster
                # rebalance time. If a specific test needs 1024 vbuckets,
                # it can be passed down as a requirement.
                'num_vbuckets': 16
        }

    @staticmethod
    def get_default_connect_args(start_args):
        return {
                'protocol': "ipv4",
                'num_nodes': start_args['num_nodes']
               }

    def as_list(self):
        return list(filter(lambda x: x is not None, self.requirements.values()))

    @testlib.no_output_decorator
    def create_cluster(self, auth, start_index, tmp_cluster_dir, kill_nodes):
        start_args = {'start_index': start_index,
                      'root_dir': f"{tmp_cluster_dir}-{start_index}"}
        start_args.update(self.get_default_start_args())
        for requirement in self.as_list():
            start_args.update(requirement.start_args)

        connect_args = {'start_index': start_index}
        connect_args.update(self.get_default_connect_args(start_args))
        for requirement in self.as_list():
            connect_args.update(requirement.connect_args)

        cluster = build_cluster(auth=auth,
                                 start_args=start_args,
                                 connect_args=connect_args,
                                 kill_nodes=kill_nodes)

        still_unmet = self.get_unmet_requirements(cluster)
        if len(still_unmet) > 0:
            unmet_str = ', '.join(str(r) for r in still_unmet)
            raise RuntimeError("Newly created cluster still has the following "
                               f"requirements unmet: {unmet_str}")
        return cluster

    # Given a cluster, checks if any requirements are not satisfied, and
    # returns the unsatisfied requirements
    @testlib.no_output_decorator
    def is_satisfiable(self, cluster):
        unsatisfied = []
        satisfiable = True
        for requirement in self.as_list():
            if not requirement.is_met(cluster):
                unsatisfied.append(requirement)
                if not requirement.can_be_met():
                    satisfiable = False
        return satisfiable, unsatisfied

    @testlib.no_output_decorator
    def get_unmet_requirements(self, cluster):
        unmet_requirements = []
        for requirement in self.as_list():
            if not requirement.is_met(cluster):
                unmet_requirements.append(requirement)
        return unmet_requirements

    # Determines whether this set of requirements will be satisfiable with a
    # cluster satisfying some 'other' ClusterRequirements
    @testlib.no_output_decorator
    def satisfied_by(self, other):
        for requirement in self.as_list():
            if not (any(requirement == other_requirement
                        for other_requirement in other.requirements)):
                return False
        return True

    @testlib.no_output_decorator
    def intersect(self, other):
        new_reqs = ClusterRequirements()
        for k in self.requirements:
            r1 = self.requirements[k]
            r2 = other.requirements[k]
            if r1 == r2:
                new_reqs.requirements[k] = r1
            elif r1 is None:
                new_reqs.requirements[k] = r2
            elif r2 is None:
                new_reqs.requirements[k] = r1
            else:
                return False, new_reqs

        return True, new_reqs


class Requirement(ABC):
    def __init__(self, **kwargs):
        # In order to provide a string representation of the requirement, we
        # need to be provided with a names and values in the form of kwargs
        self._kwargs = kwargs

        # Override to make a requirement that depends on arguments for
        # cluster_run_lib.start()
        self.start_args = {}
        # Override to make a requirement that depends on arguments for
        # cluster_run_lib.connect()
        self.connect_args = {}

    def __str__(self):
        return ",".join([f"{key}={value}"
                        for key, value in self._kwargs.items()])

    def __eq__(self, other):
        return str(self) == str(other)

    @abstractmethod
    def is_met(self, cluster):
        raise NotImplementedError()

    # Override if make_met can be called on an existing cluster
    def can_be_met(self):
        return False

    # Override to provide a way of satisfying a requirement after the cluster
    # has already been created
    def make_met(self, cluster):
        raise RuntimeError(f"Cannot change Requirement {self} after cluster "
                           f"created")


class Edition(Requirement):
    editions = ["Community", "Enterprise", "Serverless", "Provisioned"]

    def __init__(self, edition):
        super().__init__(edition=edition)
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
        elif self.edition == "Provisioned":
            self.start_args = {'force_community': False,
                               'run_provisioned': True}

    def is_met(self, cluster: Cluster):
        if self.edition == "Community":
            return not cluster.is_enterprise and not cluster.is_serverless
        elif self.edition == "Enterprise":
            return cluster.is_enterprise and not cluster.is_serverless
        elif self.edition == "Serverless":
            return cluster.is_enterprise and cluster.is_serverless
        elif self.edition == "Provisioned":
            return cluster.is_enterprise and cluster.is_provisioned


class NumNodes(Requirement):
    def __init__(self, num_nodes, num_connected):
        # We use None as a placeholder for when we want all nodes connected
        if num_connected is None:
            num_connected = num_nodes
        super().__init__(num_nodes=num_nodes, num_connected=num_connected)

        # Check requirement values are valid
        if num_nodes < 1:
            raise ValueError(f"num_nodes must be a positive integer")
        if num_connected < 1:
            raise ValueError("num_connected must be at least 1")

        self.num_nodes = num_nodes
        self.num_connected = num_connected
        self.start_args = {'num_nodes': num_nodes}
        self.connect_args = {'num_nodes': num_connected}

        if num_connected > 1:
            self.connect_args.update({'do_rebalance': True,
                                      'do_wait_for_rebalance': True})
        else:
            self.connect_args.update({'do_rebalance': False})

    def is_met(self, cluster):
        return (len(cluster.nodes) >= self.num_nodes and
                len(cluster.connected_nodes) == self.num_connected)


class MemSize(Requirement):
    def __init__(self, memsize):
        super().__init__(memsize=memsize)
        if memsize < 256:
            raise ValueError(f"memsize must be a positive integer >= 256")
        self.memsize = memsize
        self.connect_args = {'memsize': self.memsize}

    def is_met(self, cluster):
        return cluster.memsize == self.memsize

    def can_be_met(self):
        return True

    def make_met(self, cluster):
        testlib.post_succ(cluster, "/pools/default",
                          data={"memoryQuota": self.memsize})
        cluster.memsize = self.memsize


class AFamily(Requirement):
    def __init__(self, afamily):
        super().__init__(afamily=afamily)
        self.afamily = afamily
        self.connect_args = {"protocol": afamily}

    def is_met(self, cluster):
        # The address family is labeled using "inet" in /pools/nodes
        afamily_translate = {
            "ipv4": "inet",
            "ipv6": "inet6"
        }
        res = get_succ(cluster, "/pools/nodes")
        return all([node["addressFamily"] == afamily_translate[self.afamily]
                    for node in res.json()["nodes"]])


class Services(Requirement):
    def __init__(self, deploy):
        super().__init__(deploy=deploy)
        self.deploy = deploy
        self.connect_args = {"deploy": deploy}

    def is_met(self, cluster):
        for i, node in enumerate(cluster.connected_nodes):
            # We can't take information for all nodes from a single /pools/nodes
            # because we don't know which node is which
            res = get_succ(node, "/pools/nodes").json()
            this_node_services = []
            for node_info in res['nodes']:
                if 'thisNode' in node_info and node_info['thisNode']:
                    this_node_services = node_info['services']

            services_to_check = []
            if isinstance(self.deploy, list):
                services_to_check = self.deploy
            else:
                nname = f'n{i}'
                if nname in self.deploy:
                    services_to_check = self.deploy[nname]

            for s in services_to_check:
                if s not in this_node_services:
                    return False

        return True


# We are not enforcing it when creating a cluster (like by setting something
# in connect_args), because
# (1) in practice we only need to check that master password is not set, which
#     is the default behavior
# (2) it would be an extra work with no real benefit
#
# We also are not implementing make_met() because in order to do that we would
# need to use the API that we want to test (which would be strange)
class MasterPasswordState(Requirement):
    def __init__(self, state):
        super().__init__(master_password_state=state)
        self.master_password_state=state

    def is_met(self, cluster):
        for n in cluster.connected_nodes:
            r = get_succ(n, "/nodes/self/secretsManagement")
            r = r.json()
            pass_state = r['encryptionService']['passwordState']
            if pass_state != self.master_password_state:
                return False

        return True


class NumVbuckets(Requirement):
    def __init__(self, num_vbuckets):
        super().__init__(num_vbuckets=num_vbuckets)

        if num_vbuckets <= 0:
            raise ValueError("num_vbuckets needs to be > 0")

        if num_vbuckets > 1024:
            raise ValueError("num_vbuckets needs to be <= 1024")

        self.num_vbuckets = num_vbuckets
        self.start_args = {"num_vbuckets": num_vbuckets}

    def is_met(self, cluster):
        r = testlib.diag_eval(cluster,
                              code="ns_bucket:get_default_num_vbuckets()")
        default_num_vbuckets = r.content.decode('ascii')
        return int(default_num_vbuckets) == self.num_vbuckets
