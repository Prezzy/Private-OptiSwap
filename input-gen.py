inputs = open("p1-inputs", "w")

for i in range(0,200):
    inputs.write("{} 0x2\n".format(i))

inputs.write("200 0x1")

inputs.close()
