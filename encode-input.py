from protocol.InputEncoder import encodeInput

inputFile = open("p1-inputs", "r")

inputLines = inputFile.readlines()

inputFile.close()

encodedInputLines = encodeInput(inputLines, (2**32), (32)//8)


encodedInputFile = open("en-p1-inputs", "w")

encodedInputFile.write(encodedInputLines)

encodedInputFile.close()
