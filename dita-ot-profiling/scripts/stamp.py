import sys,time
t0=time.time()
for l in sys.stdin:
    if l.startswith('==>') or 'BUILD' in l:
        print(f"{time.time()-t0:7.2f} {l.rstrip()}",flush=True)
