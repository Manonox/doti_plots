import sys
import matplotlib.pyplot as plt 
import csv 
  
x = [] 
y = [] 

with open(sys.argv[1], "r") as csvfile: 
    plots = csv.reader(csvfile, delimiter = ',')
      
    subdiv = int(sys.argv[4]) if len(sys.argv) > 3 else 1
    i = 0
    for row in plots:
        if i % subdiv == 0:
            x.append(float(row[0]))
            y.append(float(row[1]))
        i += 1

plt.scatter(x, y, color = "b", marker = "x", s = 3, label = sys.argv[3])
plt.xticks([], [])
plt.yticks([], [])
plt.xlabel(sys.argv[2])
plt.ylabel(sys.argv[3])
plt.title(sys.argv[3])
plt.show()