# Reproduce the results of "Over the Wire: A Network-Level Measurement of Consumer IoT
# Update Delivery". Run `make help` for the list of targets and README.md for details.

PY    ?= python3
JOBS  ?= 12
SRC   := src/update_attribution
PAPER := latex/suit_acm_sigconf

.PHONY: help check numbers figures paper controlled retrospective keyword keyword-sample \
        entropy exposure revocation lanpush images snapshot derived all clean-cache

help:  ## list the targets
	@echo "From the data in this repository (no raw captures needed):"
	@grep -E '^(check|numbers|figures|paper):.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-15s %s\n", $$1, $$2}'
	@echo "From the raw captures (see README.md, Data):"
	@grep -E '^(controlled|retrospective|keyword|keyword-sample|entropy|exposure|revocation|lanpush|images|snapshot|derived|all|clean-cache):.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-15s %s\n", $$1, $$2}'

# --- from the versioned data in data/ --------------------------------------------------
check:  ## report which tools and raw data are available
	@$(PY) -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ needed'; print('ok   python', sys.version.split()[0])"
	@$(PY) -c "import matplotlib, cryptography; print('ok   matplotlib', matplotlib.__version__, '/ cryptography', cryptography.__version__)" \
	  || echo "MISSING Python packages: pip install -r requirements.txt"
	@kpsewhich libertine.sty >/dev/null 2>&1 && echo "ok   TeX with libertine (figures, paper)" \
	  || echo "MISSING TeX package libertine (needed for 'make figures' and 'make paper')"
	@command -v tshark >/dev/null 2>&1 && echo "ok   $$(tshark --version | head -1)" \
	  || echo "--   tshark not found (needed only for the raw-capture steps)"
	@for d in controlled/dataset retrospective/imc19_dataset controlled/firmware; do \
	  if [ -d $$d ]; then echo "ok   raw data: $$d"; else echo "--   raw data not present: $$d (raw-capture steps unavailable)"; fi; done

numbers:  ## print the numbers behind the paper's tables and key statements
	$(PY) $(SRC)/paper_numbers.py

figures:  ## regenerate the paper's data figures (Figures 4-10) in latex/.../fig/
	$(PY) $(SRC)/figures.py

paper: figures  ## build the paper PDF (needs latexmk and biber)
	cd $(PAPER) && latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex

# --- from the raw captures ---------------------------------------------------------------
controlled:  ## our captures: flows, update traffic, TLS, leaf certificates (Tables 1, 3)
	$(PY) $(SRC)/controlled_attribution.py

retrospective:  ## 2019 traces: candidates, update flows, TLS, certificates (Tables 1, 4)
	$(PY) $(SRC)/retrospective_attribution.py --jobs $(JOBS)

keyword: retrospective  ## keyword-filter baseline over all 2019 captures (Section 4.3, Figure 4)
	$(PY) $(SRC)/keyword_baseline.py --jobs $(JOBS)

keyword-sample:  ## 300-capture check of the original keyword selection (optional input)
	$(PY) $(SRC)/keyword_baseline_sample.py

entropy: controlled retrospective  ## per-flow payload entropy (Section 5.2, Figure 7)
	$(PY) $(SRC)/entropy_by_channel.py

exposure: controlled retrospective  ## what unencrypted update requests reveal (Table 5)
	$(PY) $(SRC)/exposure.py

revocation: controlled retrospective  ## revocation sources, OCSP stapling, lookups (Table 6)
	$(PY) $(SRC)/revocation.py --jobs $(JOBS)

lanpush:  ## is reolink-cam's local push encrypted? (Section 5.2, printed)
	$(PY) $(SRC)/lan_push_check.py

images:  ## image protection of the controlled devices' images (Section 5.4, Figure 10)
	$(PY) src/image_protection/integrity_bitflip.py

snapshot:  ## rebuild the cipher-suite table from the dated ciphersuite.info response
	$(PY) $(SRC)/ciphersuite_snapshot.py

derived: controlled retrospective keyword entropy exposure revocation images  ## rebuild all of data/derived
	@echo "data/derived rebuilt; run 'make numbers figures' to use it"

all: derived lanpush figures numbers paper  ## everything, from raw captures to the PDF

clean-cache:  ## delete the tshark extraction caches (the next raw-capture run starts over)
	rm -rf cache/
