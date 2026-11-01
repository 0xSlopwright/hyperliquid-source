import os,sys,unittest
import shared_cache as state
state.buffers[__name__]=bytearray(131072)
state.event("module_import",module=__name__)
class Observed(unittest.TestCase):
 def test_real_process_observation(self):
  state.event("test",module=__name__)
  print("PEER_STDOUT_"+__name__,flush=True)
  print("PEER_STDERR_"+__name__,file=sys.stderr,flush=True)
  self.assertEqual(len(state.buffers[__name__]),131072)
  self.assertTrue(sys.flags.dont_write_bytecode)
  self.assertEqual(sys.flags.optimize,1)
 def test_standard_skip(self):
  self.skipTest("independent peer skip")
