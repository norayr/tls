DEPEND = github.com/norayr/strutils github.com/norayr/base64 github.com/norayr/Internet github.com/norayr/http

VOC = voc
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir_path := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
$(info $$mkfile_path is [${mkfile_path}])
$(info $$mkfile_dir_path is [${mkfile_dir_path}])
ifndef BUILD
BUILD="build"
endif
build_dir_path := $(mkfile_dir_path)/$(BUILD)
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
BLD := $(mkfile_dir_path)/build
DPD  =  deps
ifndef DPS
DPS := $(mkfile_dir_path)/$(DPD)
endif
TESTS = TLSTestBytes TLSTestSHA256 TLSTestHKDF TLSTestSHA512 TLSTestNum TLSTestNumBig TLSTestECDSA256 TLSTestECDSA384 TLSTestECDSA521 TLSTestECDH TLSTestX25519 TLSTestCrypto TLSTestAESGCM TLSTestGCM TLSTestRecords TLSTestHandshake TLSTestHRR TLSTestKeys TLSTestFinished TLSTestPEM TLSTestTLS13Certs TLSTestASN1 TLSTestX509 TLSTestRSA1 TLSTestRSA2 TLSTestRSA3 TLSTestChain TLSTestX509Names TLSTestIP TLSTestEncHandshake TLSTestClientFin TLSTestApplication

all: get_deps build_deps buildThis

get_deps:
	@for i in $(DEPEND); do \
			if [ -d "$(DPS)/$${i}" ]; then \
				 cd "$(DPS)/$${i}"; \
				 git pull; \
				 cd - ;    \
				 else \
				 mkdir -p "$(DPS)/$${i}"; \
				 cd "$(DPS)/$${i}"; \
				 cd .. ; \
				 git clone "https://$${i}"; \
				 cd - ; \
			fi; \
	done

build_deps:
	mkdir -p $(BLD)
	cd $(BLD); \
	for i in $(DEPEND); do \
		if [ -f "$(DPS)/$${i}/GNUmakefile" ]; then \
			make -f "$(DPS)/$${i}/GNUmakefile" BUILD=$(BLD); \
		else \
			make -f "$(DPS)/$${i}/Makefile" BUILD=$(BLD); \
		fi; \
	done

buildThis:
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/BIT.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSBytes.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestBytes.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSSHA256.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSHKDF.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestSHA256.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestHKDF.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSSHA512.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestSHA512.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSNum.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestNum.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestNumBig.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSECDSA.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestECDSA256.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestECDSA384.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestECDSA521.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestECDH.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX25519.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestX25519.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestCrypto.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSAESGCM.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestAESGCM.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestGCM.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Records.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestRecords.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Handshake.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestHandshake.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestHRR.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Keys.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestKeys.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Finished.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestFinished.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSBase64.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSPEM.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestPEM.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Certs.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestTLS13Certs.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSASN1.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestASN1.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX509.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestX509.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX509Validity.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSRSA.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestRSA1.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestRSA2.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestRSA3.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX509Names.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX509Ext.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSSig.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSNameConstraints.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSX509Chain.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSCABundle.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestChain.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestX509Names.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestIP.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13EncHandshake.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestEncHandshake.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13ClientFinished.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestClientFin.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Application.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/TLSTestApplication.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Random.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLSNow.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/TLS13Live.Mod
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/httpsPure.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/testHttpsPure.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/tlsConnect.Mod
	cd $(BUILD) && $(VOC) -m $(mkfile_dir_path)/src/httpsGet.Mod
tests:
	@cd $(BUILD) && fails=0; for t in $(TESTS); do \
		out=$$(TLS_TEST_CERTS=$(mkfile_dir_path)/test/certs ./$$t 2>&1); \
		echo "$$out" | tail -n 1; \
		if echo "$$out" | grep -q 'FAIL\| [1-9][0-9]* failed'; then \
			echo "$$out" | grep 'FAIL\|failed'; fails=$$((fails + 1)); \
		fi; \
	done; \
	echo "$$fails test programs failed"; test $$fails = 0

clean:
	if [ -d "$(BUILD)" ]; then rm -rf $(BLD); fi
