DEPEND = github.com/norayr/strutils github.com/norayr/base64 github.com/norayr/Internet github.com/norayr/http
#DEPEND = github.com/norayr/Internet github.com/norayr/http

VOC = /opt/voc/bin/voc
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
all: get_deps build_deps buildThis

get_deps:
	@for i in $(DEPEND); do \
#			if [ -d "$(DPS)/$${i}" ]; then \
#				 cd "$(DPS)/$${i}"; \
#				 git pull; \
#				 cd - ;    \
#				 else \
				 mkdir -p "$(DPS)/$${i}"; \
				 cd "$(DPS)/$${i}"; \
				 cd .. ; \
				 git clone "https://$${i}"; \
				 cd - ; \
#			fi; \
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
	cd $(BUILD) && $(VOC) -s ../src/BIT.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSBytes.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestBytes.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSSHA256.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSHKDF.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestSHA256.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestHKDF.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSSHA512.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestSHA512.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSNum.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestNum.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestNumBig.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSECDSA.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestECDSA256.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestECDSA384.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestECDSA521.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestECDH.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX25519.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestX25519.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestCrypto.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSAESGCM.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestAESGCM.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestGCM.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Records.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestRecords.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Handshake.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestHandshake.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestHRR.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Keys.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestKeys.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Finished.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestFinished.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSBase64.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSPEM.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestPEM.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Certs.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestTLS13Certs.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSASN1.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestASN1.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX509.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestX509.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX509Validity.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSRSA.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestRSA1.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestRSA2.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestRSA3.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX509Names.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX509Ext.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSSig.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSNameConstraints.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSX509Chain.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSCABundle.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestChain.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestX509Names.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestIP.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13EncHandshake.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestEncHandshake.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13ClientFinished.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestClientFin.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Application.Mod
	cd $(BUILD) && $(VOC) -m ../src/TLSTestApplication.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Random.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLSNow.Mod
	cd $(BUILD) && $(VOC) -s ../src/TLS13Live.Mod
	cd $(BUILD) && $(VOC) -s ../src/httpsPure.Mod
	cd $(BUILD) && $(VOC) -m ../src/testHttpsPure.Mod
	cd $(BUILD) && $(VOC) -m ../src/tlsConnect.Mod
	cd $(BUILD) && $(VOC) -m ../src/httpsGet.Mod
tests:
	cd $(BUILD) && $(VOC) $(mkfile_dir_path)/test/TestEncryption.Mod -m
	cd $(BUILD) && $(VOC) $(mkfile_dir_path)/test/TestCrypt.Mod -m
	cd $(BUILD) && $(VOC) $(mkfile_dir_path)/test/TestCompressEncrypt.Mod -m
	#build/testList

clean:
	if [ -d "$(BUILD)" ]; then rm -rf $(BLD); fi
