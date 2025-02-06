CFILE = yes.c
BIN = test
OUTPUT = out
TXT = $(wildcard *.txt)

all:
	make test
	python3 split.py

test:
	gcc -o ${BIN} ${CFILE}

	
# Clean target 
clean:
	@echo "Cleaning up files..."
	@rm -rf $(BIN) $(OUT) result $(TXT) 

