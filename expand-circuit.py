from protocol.CircuitTransformer import transform

circuitFile = open("one-matrix-p1-b32.arith", "r")

circuitLines = circuitFile.readlines()


expandedCircuitLines = transform(circuitLines, (2**32), (32)//8)

expandedCircuitFile = open("ex-one-matrix-p1-b32.arith", "w")

expandedCircuitFile.write(expandedCircuitLines[1])
