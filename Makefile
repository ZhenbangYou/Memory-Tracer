interpose.so: interpose.cpp
	g++ -o $@ -shared -fPIC $< -ldl -pthread -O3 -std=c++26 -D_GNU_SOURCE

clean:
	rm interpose.so

.PHONY: clean