"""Verification fixtures keep a service on its serving loop across requests."""
import asyncio
import contextlib
import unittest
from pathlib import Path
from unittest import mock

import test_verification_api as seam
import test_verification_api_boundary as boundary


class FixtureLifecycleTests(unittest.TestCase):
    def test_each_fixture_owns_a_separate_loop(self):
        loops = []
        for base, drive in ((seam.Scenario, 'drive'),
                            (boundary.VerificationAPIFixture, 'run_async')):
            for _ in range(2):
                fixture = type('Fixture', (base, unittest.TestCase), {})()
                fixture.setUp()
                try:
                    async def current():
                        return asyncio.get_running_loop()
                    loop = getattr(fixture, drive)(current())
                    self.assertFalse(loop.is_closed())
                    loops.append(loop)
                finally:
                    fixture.doCleanups()
                self.assertTrue(loop.is_closed())
        self.assertEqual(len({id(loop) for loop in loops}), 4)

    def test_exception_cleanup_drains_on_serving_loop_before_removing_store(self):
        for base, drive in ((seam.Scenario, 'drive'),
                            (boundary.VerificationAPIFixture, 'run_async')):
            with self.subTest(fixture=base.__name__):
                fixture = type('Fixture', (base, unittest.TestCase), {})()
                fixture.setUp()
                services = ([fixture.api] if base is seam.Scenario else
                            [service for app in [fixture.serving()['app']]
                             for service in (app.verification_api, app.refusal_audit_dispatch)])
                seen = []
                tasks = []
                loops = []

                async def leftover():
                    try:
                        await asyncio.Event().wait()
                    finally:
                        seen.append('task_finished')

                async def failed_request():
                    loops.append(asyncio.get_running_loop())
                    tasks.append(asyncio.create_task(leftover()))
                    await asyncio.sleep(0)
                    raise ValueError('fixture scenario failed')

                def observer(service):
                    original = service.wait_idle

                    async def drained():
                        self.assertIs(asyncio.get_running_loop(), loops[0])
                        self.assertFalse(loops[0].is_closed())
                        self.assertTrue(service.closed)
                        self.assertTrue(Path(fixture.temp.name).exists())
                        await original()
                        seen.append('drained')
                    return drained

                try:
                    with self.assertRaisesRegex(ValueError, 'fixture scenario failed'):
                        getattr(fixture, drive)(failed_request())
                    with contextlib.ExitStack() as stack:
                        for service in services:
                            stack.enter_context(mock.patch.object(service, 'wait_idle',
                                                                  new=observer(service)))
                        self.assertTrue(fixture.doCleanups())
                    self.assertEqual(seen, ['drained'] * len(services) + ['task_finished'])
                    self.assertTrue(all(task.done() for task in tasks))
                    self.assertEqual(asyncio.all_tasks(loops[0]), set())
                    self.assertTrue(loops[0].is_closed())
                    self.assertFalse(Path(fixture.temp.name).exists())
                finally:
                    fixture.doCleanups()

    def test_seam_repeated_requests_share_the_exact_loop(self):
        fixture = type('Fixture', (seam.Scenario, unittest.TestCase), {})()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        loops = []
        original = fixture.api.handle

        async def observed(*args, **kwargs):
            loops.append(asyncio.get_running_loop())
            return await original(*args, **kwargs)

        with mock.patch.object(fixture.api, 'handle', new=observed):
            for _ in range(2):
                answer = fixture.drive(fixture.call(
                    'GET', seam.BINDING,
                    query=f"action_id={fixture.case['action_id']}".encode()))
                self.assertEqual(answer.status, 200)
        self.assertIs(loops[0], loops[1])

    def test_boundary_setup_and_request_share_the_exact_loop(self):
        fixture = boundary.QueryTests()
        self.addCleanup(fixture.doCleanups)
        calls = []
        original = boundary.VerificationAPI.handle

        async def observed(service, *args, **kwargs):
            calls.append((service, asyncio.get_running_loop()))
            return await original(service, *args, **kwargs)

        with mock.patch.object(boundary.VerificationAPI, 'handle', new=observed):
            fixture.setUp()
            answer = fixture.run_async(fixture.get(fixture.case))
        self.assertEqual(answer.status, 200)
        self.assertIs(calls[0][0], calls[1][0])
        self.assertIs(calls[0][1], calls[1][1])


if __name__ == '__main__':
    unittest.main()
