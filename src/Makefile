CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -O2 -I../include/
LDFLAGS = -L../libs/ -lWinDivert -lws2_32 -lcurl

OBJDIR  = build
SRC     = $(wildcard *.c)
OBJS    = $(patsubst %.c,$(OBJDIR)/%.o,$(SRC))
TARGET  = $(OBJDIR)/proxydlp.exe

all: $(OBJDIR) $(TARGET)

# Ensure the object directory exists
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Link the executable inside the build directory
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile each .c into the object directory
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR)
