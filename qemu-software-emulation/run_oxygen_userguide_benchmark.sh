#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/oxygen-exp}"
DITA_VER="${DITA_VER:-4.3.1}"
USERGUIDE_REPO="https://github.com/oxygenxml/userguide.git"

mkdir -p "$WORKDIR"
cd "$WORKDIR"

if ! command -v qemu-aarch64-static >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y qemu-user-static libc6-arm64-cross
fi

if [ ! -d userguide ]; then
  git clone --depth 1 "$USERGUIDE_REPO" userguide
fi

if [ ! -d "dita-ot-${DITA_VER}" ]; then
  curl -L -o dita.zip "https://github.com/dita-ot/dita-ot/releases/download/${DITA_VER}/dita-ot-${DITA_VER}.zip"
  unzip -q dita.zip
fi

if [ ! -d jre-aarch64 ]; then
  curl -L -o jre-aarch64.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/aarch64/jre/hotspot/normal/eclipse"
  mkdir -p jre-aarch64
  tar -xzf jre-aarch64.tar.gz -C jre-aarch64 --strip-components=1
fi

mkdir -p qemu-java/bin
cat > qemu-java/bin/java <<WRAP
#!/usr/bin/env bash
exec qemu-aarch64-static -L /usr/aarch64-linux-gnu "$WORKDIR/jre-aarch64/bin/java" "\$@"
WRAP
chmod +x qemu-java/bin/java

cd "$WORKDIR/userguide"
WORKDIR="$WORKDIR" DITA_VER="$DITA_VER" python - <<'PY'
import os, subprocess, time

workdir = os.environ['WORKDIR']
dita_ver = os.environ['DITA_VER']
dita = f'{workdir}/dita-ot-{dita_ver}/bin/dita'

def run(label, outdir, env=None):
    env = os.environ.copy() if env is None else env
    cmd=[
      dita,
      '--input=DITA/UserManual.ditamap',
      '--format=html5',
      '--filter=DITA/ditaval/editor-sa.ditaval',
      f'--output={outdir}'
    ]
    subprocess.run(['rm','-rf',outdir], check=True)
    start=time.perf_counter()
    p=subprocess.run(cmd, env=env)
    elapsed=time.perf_counter()-start
    print(f'{label}_REAL_SECONDS={elapsed:.3f}')
    if p.returncode != 0:
        raise SystemExit(p.returncode)

run('NATIVE', 'out-native')

qemu_env=os.environ.copy()
qemu_env['JAVACMD']=f'{workdir}/qemu-java/bin/java'
qemu_env.pop('JAVA_HOME', None)
run('QEMU', 'out-qemu', qemu_env)
PY
