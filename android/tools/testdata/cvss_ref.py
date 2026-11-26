import math, itertools
from decimal import Decimal, ROUND_CEILING
AV={'N':0.85,'A':0.62,'L':0.55,'P':0.2}; AC={'L':0.77,'H':0.44}; UI={'N':0.85,'R':0.62}; CIA={'H':0.56,'L':0.22,'N':0.0}
PRU={'N':0.85,'L':0.62,'H':0.27}; PRC={'N':0.85,'L':0.68,'H':0.5}
def ru31(x):
    i = round(x*100000)
    return i/100000.0 if i % 10000 == 0 else (math.floor(i/10000)+1)/10.0
def ru30(x): return math.ceil(x*10)/10
def score(v, ver):
    av,ac,pr,ui,s,c,i,a = v
    iss = 1-(1-CIA[c])*(1-CIA[i])*(1-CIA[a])
    imp = 7.52*(iss-0.029)-3.25*(iss-0.02)**15 if s=='C' else 6.42*iss
    ex = 8.22*AV[av]*AC[ac]*(PRC if s=='C' else PRU)[pr]*UI[ui]
    ru = ru31 if ver=='3.1' else ru30
    if imp<=0: return 0.0
    return ru(min(1.08*(imp+ex),10)) if s=='C' else ru(min(imp+ex,10))
known = ["N L N N U H H H","N L N N C H H H","N L N N U H N N","N L N R C L L N","L L L N U H H H","N H N N U H H H","N L L R U L N N","P H H R U N N N","A L N N U N N H","N L H N C H H H"]
for k in known:
    v=k.split(); print("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s"%tuple(v), score(v,'3.1'))
# differences between 3.0 and 3.1 roundup
diff=[]
for v in itertools.product('NALP','LH','NLH','NR','UC','HLN','HLN','HLN'):
    a,b=score(v,'3.0'),score(v,'3.1')
    if abs(a-b)>1e-9: diff.append((v,a,b))
print(len(diff), diff[:5])
