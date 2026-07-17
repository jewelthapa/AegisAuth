# =====================================================
# AegisAuth — Privilege-Separated Authentication Framework
# Build Script
# =====================================================

CC = gcc

CFLAGS = -Wall -Wextra -O2

LIBS = -lcrypt

TARGETS = Frontend Backend

all: $(TARGETS)

Frontend: Frontend.c common.h
	$(CC) $(CFLAGS) -o Frontend Frontend.c

Backend: Backend.c common.h
	$(CC) $(CFLAGS) -o Backend Backend.c $(LIBS)

clean:
	rm -f Frontend Backend

rebuild: clean all

run:
	sudo ./Frontend

adduser:
	sudo ./Backend adduser jewel password123

.PHONY: all clean rebuild run adduser
