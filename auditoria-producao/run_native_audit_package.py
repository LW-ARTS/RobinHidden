"""Portable focused native audit reproduction; no operator data or networking."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ["test_native_signer.py", "test_native_secp_security.py", "test_native_review_regressions.py",
           "test_native_aes.py", "test_native_aes_security.py", "test_custody_verifier.py"]

def main():
    with tempfile.TemporaryDirectory(prefix="rh-native-public-audit-") as temp:
        target = Path(temp)
        shutil.copytree(ROOT / "rh", target / "rh", ignore=shutil.ignore_patterns("__pycache__"))
        folder = target / "auditoria-producao"
        folder.mkdir()
        for name in SCRIPTS + ["verify_custody_local.py"]:
            shutil.copyfile(ROOT / "auditoria-producao" / name, folder / name)
        runner = '''import runpy,sys
from pathlib import Path
def guard(event,args):
    if event.startswith('socket.'):raise PermissionError('Audit package network blocked')
    if event=='open' and isinstance(args[0],(str,bytes)):
        path=Path(args[0]).resolve()
        if 'data' in path.parts:raise PermissionError('Operator data blocked')
sys.addaudithook(guard)
script=sys.argv[1]
sys.argv=[script]
runpy.run_path(script,run_name='__main__')
'''
        rows = []
        for name in SCRIPTS:
            result = subprocess.run([sys.executable, "-c", runner, str(folder / name)], cwd=target)
            rows.append({"suite": name, "exit_code": result.returncode})
        print(json.dumps({"suites": rows, "operator_data_copied": False, "network": False}, indent=2))
        return int(any(row["exit_code"] for row in rows))

if __name__ == "__main__":
    sys.exit(main())
