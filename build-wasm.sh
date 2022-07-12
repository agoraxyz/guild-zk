#!/bin/sh
ACCESS_HEADER_TRIMMED="${ACCESS_HEADER#"${ACCESS_HEADER%%[![:space:]]*}"}"
OUT_DIR="wasm-output"
TARGET_BRANCH=${TARGET_BRANCH##*/}

WASM_DIRS=("agora-zkp-ecdsa" "agora-zkp-triptych")

for WASM_DIR in ${WASM_DIRS[@]}
do
	BRANCH_NAME=${WASM_DIR}@${TARGET_BRANCH}

	wasm-pack build ${WASM_DIR} --target bundler --out-dir ${OUT_DIR}

	cd ${WASM_DIR}/${OUT_DIR}
	rm -f .gitignore
	git init
	#git remote add origin https://${ACCESS_HEADER_TRIMMED}@github.com/agoraxyz/agora-wasm-hub.git
	git remote add origin https://github.com/agoraxyz/agora-wasm-hub.git
	git branch -M ${BRANCH_NAME}
	git add -A
	git commit -m "Auto-generated wasm code"
	git push -uf origin ${BRANCH_NAME}

	cd ../..
	rm -rf ${WASM_DIR}/${OUT_DIR}
done
