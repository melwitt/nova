# Copyright (c) 2012 Rackspace Hosting
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Tests For CellsScheduler
"""
import time

from oslo.config import cfg

from nova.cells import filters
from nova.cells import weights
from nova.compute import vm_states
from nova import context
from nova import db
from nova import exception
from nova.openstack.common import uuidutils
from nova import test
from nova.tests.cells import fakes

CONF = cfg.CONF
CONF.import_opt('scheduler_retries', 'nova.cells.scheduler', group='cells')
CONF.import_opt('scheduler_filter_classes', 'nova.cells.scheduler',
                group='cells')
CONF.import_opt('scheduler_weight_classes', 'nova.cells.scheduler',
                group='cells')


class FakeFilterClass1(filters.BaseCellFilter):
    pass


class FakeFilterClass2(filters.BaseCellFilter):
    pass


class FakeWeightClass1(weights.BaseCellWeigher):
    pass


class FakeWeightClass2(weights.BaseCellWeigher):
    pass


class CellsSchedulerTestCase(test.TestCase):
    """Test case for CellsScheduler class."""

    def setUp(self):
        super(CellsSchedulerTestCase, self).setUp()
        self.flags(scheduler_filter_classes=[], scheduler_weight_classes=[],
                   group='cells')
        self._init_cells_scheduler()

    def _init_cells_scheduler(self):
        fakes.init(self)
        self.msg_runner = fakes.get_message_runner('api-cell')
        self.scheduler = self.msg_runner.scheduler
        self.state_manager = self.msg_runner.state_manager
        self.my_cell_state = self.state_manager.get_my_state()
        self.ctxt = context.RequestContext('fake', 'fake')
        instance_uuids = []
        for x in xrange(3):
            instance_uuids.append(uuidutils.generate_uuid())
        self.instance_uuids = instance_uuids
        self.request_spec = {'instance_uuids': instance_uuids,
                             'other': 'stuff'}

    def test_create_instances_here(self):
        # Just grab the first instance type
        inst_type = db.instance_type_get(self.ctxt, 1)
        image = {'properties': {}}
        instance_props = {'hostname': 'meow',
                          'display_name': 'moo',
                          'image_ref': 'fake_image_ref',
                          'user_id': self.ctxt.user_id,
                          'project_id': self.ctxt.project_id}
        request_spec = {'instance_type': inst_type,
                        'image': image,
                        'security_group': ['default'],
                        'block_device_mapping': [],
                        'instance_properties': instance_props,
                        'instance_uuids': self.instance_uuids}

        call_info = {'uuids': []}

        def _fake_instance_update_at_top(_ctxt, instance):
            call_info['uuids'].append(instance['uuid'])

        self.stubs.Set(self.msg_runner, 'instance_update_at_top',
                       _fake_instance_update_at_top)

        self.scheduler._create_instances_here(self.ctxt, request_spec)
        self.assertEqual(self.instance_uuids, call_info['uuids'])

        for instance_uuid in self.instance_uuids:
            instance = db.instance_get_by_uuid(self.ctxt, instance_uuid)
            self.assertEqual('meow', instance['hostname'])
            self.assertEqual('moo-%s' % instance['uuid'],
                             instance['display_name'])
            self.assertEqual('fake_image_ref', instance['image_ref'])

    def test_run_instance_selects_child_cell(self):
        # Make sure there's no capacity info so we're sure to
        # select a child cell
        our_cell_info = self.state_manager.get_my_state()
        our_cell_info.capacities = {}

        call_info = {'times': 0}

        orig_fn = self.msg_runner.schedule_run_instance

        def msg_runner_schedule_run_instance(ctxt, target_cell,
                host_sched_kwargs):
            # This gets called twice.  Once for our running it
            # in this cell.. and then it'll get called when the
            # child cell is picked.  So, first time.. just run it
            # like normal.
            if not call_info['times']:
                call_info['times'] += 1
                return orig_fn(ctxt, target_cell, host_sched_kwargs)
            call_info['ctxt'] = ctxt
            call_info['target_cell'] = target_cell
            call_info['host_sched_kwargs'] = host_sched_kwargs

        self.stubs.Set(self.msg_runner, 'schedule_run_instance',
                msg_runner_schedule_run_instance)

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {}}
        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)

        self.assertEqual(self.ctxt, call_info['ctxt'])
        self.assertEqual(host_sched_kwargs, call_info['host_sched_kwargs'])
        child_cells = self.state_manager.get_child_cells()
        self.assertIn(call_info['target_cell'], child_cells)

    def test_run_instance_selects_current_cell(self):
        # Make sure there's no child cells so that we will be
        # selected
        self.state_manager.child_cells = {}

        call_info = {}

        def fake_create_instances_here(ctxt, request_spec):
            call_info['ctxt'] = ctxt
            call_info['request_spec'] = request_spec

        def fake_rpc_run_instance(ctxt, **host_sched_kwargs):
            call_info['host_sched_kwargs'] = host_sched_kwargs

        self.stubs.Set(self.scheduler, '_create_instances_here',
                fake_create_instances_here)
        self.stubs.Set(self.scheduler.scheduler_rpcapi,
                       'run_instance', fake_rpc_run_instance)

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {},
                             'other': 'stuff'}
        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)

        self.assertEqual(self.ctxt, call_info['ctxt'])
        self.assertEqual(self.request_spec, call_info['request_spec'])
        self.assertEqual(host_sched_kwargs, call_info['host_sched_kwargs'])

    def test_run_instance_retries_when_no_cells_avail(self):
        self.flags(scheduler_retries=7, group='cells')

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {}}

        call_info = {'num_tries': 0, 'errored_uuids': []}

        def fake_run_instance(message, host_sched_kwargs):
            call_info['num_tries'] += 1
            raise exception.NoCellsAvailable()

        def fake_sleep(_secs):
            return

        def fake_instance_update(ctxt, instance_uuid, values):
            self.assertEqual(vm_states.ERROR, values['vm_state'])
            call_info['errored_uuids'].append(instance_uuid)

        self.stubs.Set(self.scheduler, '_run_instance', fake_run_instance)
        self.stubs.Set(time, 'sleep', fake_sleep)
        self.stubs.Set(db, 'instance_update', fake_instance_update)

        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)

        self.assertEqual(8, call_info['num_tries'])
        self.assertEqual(self.instance_uuids, call_info['errored_uuids'])

    def test_run_instance_on_random_exception(self):
        self.flags(scheduler_retries=7, group='cells')

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {}}

        call_info = {'num_tries': 0,
                     'errored_uuids1': [],
                     'errored_uuids2': []}

        def fake_run_instance(message, host_sched_kwargs):
            call_info['num_tries'] += 1
            raise test.TestingException()

        def fake_instance_update(ctxt, instance_uuid, values):
            self.assertEqual(vm_states.ERROR, values['vm_state'])
            call_info['errored_uuids1'].append(instance_uuid)

        def fake_instance_update_at_top(ctxt, instance):
            self.assertEqual(vm_states.ERROR, instance['vm_state'])
            call_info['errored_uuids2'].append(instance['uuid'])

        self.stubs.Set(self.scheduler, '_run_instance', fake_run_instance)
        self.stubs.Set(db, 'instance_update', fake_instance_update)
        self.stubs.Set(self.msg_runner, 'instance_update_at_top',
                       fake_instance_update_at_top)

        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)
        # Shouldn't retry
        self.assertEqual(1, call_info['num_tries'])
        self.assertEqual(self.instance_uuids, call_info['errored_uuids1'])
        self.assertEqual(self.instance_uuids, call_info['errored_uuids2'])

    def test_cells_filter_args_correct(self):
        # Re-init our fakes with some filters.
        our_path = 'nova.tests.cells.test_cells_scheduler'
        cls_names = [our_path + '.' + 'FakeFilterClass1',
                     our_path + '.' + 'FakeFilterClass2']
        self.flags(scheduler_filter_classes=cls_names, group='cells')
        self._init_cells_scheduler()

        # Make sure there's no child cells so that we will be
        # selected.  Makes stubbing easier.
        self.state_manager.child_cells = {}

        call_info = {}

        def fake_create_instances_here(ctxt, request_spec):
            call_info['ctxt'] = ctxt
            call_info['request_spec'] = request_spec

        def fake_rpc_run_instance(ctxt, **host_sched_kwargs):
            call_info['host_sched_kwargs'] = host_sched_kwargs

        def fake_get_filtered_objs(filter_classes, cells, filt_properties):
            call_info['filt_classes'] = filter_classes
            call_info['filt_cells'] = cells
            call_info['filt_props'] = filt_properties
            return cells

        self.stubs.Set(self.scheduler, '_create_instances_here',
                fake_create_instances_here)
        self.stubs.Set(self.scheduler.scheduler_rpcapi,
                       'run_instance', fake_rpc_run_instance)
        filter_handler = self.scheduler.filter_handler
        self.stubs.Set(filter_handler, 'get_filtered_objects',
                       fake_get_filtered_objs)

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {},
                             'other': 'stuff'}

        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)
        # Our cell was selected.
        self.assertEqual(self.ctxt, call_info['ctxt'])
        self.assertEqual(self.request_spec, call_info['request_spec'])
        self.assertEqual(host_sched_kwargs, call_info['host_sched_kwargs'])
        # Filter args are correct
        expected_filt_props = {'context': self.ctxt,
                               'scheduler': self.scheduler,
                               'routing_path': self.my_cell_state.name,
                               'host_sched_kwargs': host_sched_kwargs,
                               'request_spec': self.request_spec}
        self.assertEqual(expected_filt_props, call_info['filt_props'])
        self.assertEqual([FakeFilterClass1, FakeFilterClass2],
                         call_info['filt_classes'])
        self.assertEqual([self.my_cell_state], call_info['filt_cells'])

    def test_cells_filter_returning_none(self):
        # Re-init our fakes with some filters.
        our_path = 'nova.tests.cells.test_cells_scheduler'
        cls_names = [our_path + '.' + 'FakeFilterClass1',
                     our_path + '.' + 'FakeFilterClass2']
        self.flags(scheduler_filter_classes=cls_names, group='cells')
        self._init_cells_scheduler()

        # Make sure there's no child cells so that we will be
        # selected.  Makes stubbing easier.
        self.state_manager.child_cells = {}

        call_info = {'scheduled': False}

        def fake_create_instances_here(ctxt, request_spec):
            # Should not be called
            call_info['scheduled'] = True

        def fake_get_filtered_objs(filter_classes, cells, filt_properties):
            # Should cause scheduling to be skipped.  Means that the
            # filter did it.
            return None

        self.stubs.Set(self.scheduler, '_create_instances_here',
                fake_create_instances_here)
        filter_handler = self.scheduler.filter_handler
        self.stubs.Set(filter_handler, 'get_filtered_objects',
                       fake_get_filtered_objs)

        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, {})
        self.assertFalse(call_info['scheduled'])

    def test_cells_weight_args_correct(self):
        # Re-init our fakes with some filters.
        our_path = 'nova.tests.cells.test_cells_scheduler'
        cls_names = [our_path + '.' + 'FakeWeightClass1',
                     our_path + '.' + 'FakeWeightClass2']
        self.flags(scheduler_weight_classes=cls_names, group='cells')
        self._init_cells_scheduler()

        # Make sure there's no child cells so that we will be
        # selected.  Makes stubbing easier.
        self.state_manager.child_cells = {}

        call_info = {}

        def fake_create_instances_here(ctxt, request_spec):
            call_info['ctxt'] = ctxt
            call_info['request_spec'] = request_spec

        def fake_rpc_run_instance(ctxt, **host_sched_kwargs):
            call_info['host_sched_kwargs'] = host_sched_kwargs

        def fake_get_weighed_objs(weight_classes, cells, filt_properties):
            call_info['weight_classes'] = weight_classes
            call_info['weight_cells'] = cells
            call_info['weight_props'] = filt_properties
            return [weights.WeightedCell(cells[0], 0.0)]

        self.stubs.Set(self.scheduler, '_create_instances_here',
                fake_create_instances_here)
        self.stubs.Set(self.scheduler.scheduler_rpcapi,
                       'run_instance', fake_rpc_run_instance)
        weight_handler = self.scheduler.weight_handler
        self.stubs.Set(weight_handler, 'get_weighed_objects',
                       fake_get_weighed_objs)

        host_sched_kwargs = {'request_spec': self.request_spec,
                             'filter_properties': {},
                             'other': 'stuff'}

        self.msg_runner.schedule_run_instance(self.ctxt,
                self.my_cell_state, host_sched_kwargs)
        # Our cell was selected.
        self.assertEqual(self.ctxt, call_info['ctxt'])
        self.assertEqual(self.request_spec, call_info['request_spec'])
        self.assertEqual(host_sched_kwargs, call_info['host_sched_kwargs'])
        # Weight args are correct
        expected_filt_props = {'context': self.ctxt,
                               'scheduler': self.scheduler,
                               'routing_path': self.my_cell_state.name,
                               'host_sched_kwargs': host_sched_kwargs,
                               'request_spec': self.request_spec}
        self.assertEqual(expected_filt_props, call_info['weight_props'])
        self.assertEqual([FakeWeightClass1, FakeWeightClass2],
                         call_info['weight_classes'])
        self.assertEqual([self.my_cell_state], call_info['weight_cells'])
