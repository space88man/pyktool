CXXFLAGS = -fpermissive
GENERATORS = twofish gen_pbev1

all: $(GENERATORS)


twofish: twofish.o
	$(CXX) -o $@ $< -lcryptopp

gen_pbev1: gen_pbev1.o
	$(CC) -o $@ $< -lcrypto


clean:
	rm -rf *.o $(GENERATORS)

.PHONY: clean

