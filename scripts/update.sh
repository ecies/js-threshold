#!/bin/sh
pnpm update
cd tests-browser && pnpm update && cd ..
cd example/runtime && pnpm update && cd ../..
