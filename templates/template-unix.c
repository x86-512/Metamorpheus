int main() {
  char shellcode[] = "";
  char *executable = &shellcode;
  void (*run)() = (void (*)())executable;
  run();
  return 0;
}
