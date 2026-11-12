"""The runner must retain partial output when a command times out."""
from pathlib import Path
import json,runpy,subprocess,sys,tempfile
from unittest.mock import patch
script=Path(__file__).with_name('run.py')
with tempfile.TemporaryDirectory() as temp:
    out=Path(temp)/'timeout'
    error=subprocess.TimeoutExpired(['cc'],60,output=b'partial compiler output',stderr=b'partial diagnostic')
    with patch.object(sys,'argv',[str(script),'--out',str(out)]),patch('platform.platform',return_value='timeout-test'),patch('subprocess.run',side_effect=error):
        try:runpy.run_path(str(script),run_name='__main__')
        except SystemExit:pass
        else:raise AssertionError('timeout reported as completion')
    record=json.loads((out/'manifest.json').read_text())
    assert record['compile_timeout'] and record['compile_exit']==124
    assert 'run_exit' not in record
    assert (out/'compile.stdout.log').read_text()=='partial compiler output'
    assert (out/'compile.stderr.log').read_text()=='partial diagnostic'
print('runner timeout provenance check passed')
