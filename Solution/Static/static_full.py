from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer 
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_validate
from sklearn.metrics import confusion_matrix,accuracy_score, f1_score,precision_score, recall_score
from sklearn.svm import SVC
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
import csv

##################################API Read######################
api_all_x =[]
field =[]
def api_read(file):
    with open(file,'r') as f:
        read = csv.reader(f)
        field = next(read)
        for row in read:
    #         print(row[0])
            if row[0] and row[0].strip() :
                api_all_x.append(row[0].strip())
api_read('file_mal_api_1.csv')
api_read('file_ben_api_1.csv')
df_api = pd.DataFrame(api_all_x)



##################################PE Read######################
feature = []
def feat_read(file):
    field =[]
    with open(file,'r') as f:
        read = csv.reader(f)
        field = next(read)
        for row in read:
            dic = {}
            for e in range(len(row)):
                dic[field[e]]= row[e]
            feature.append(dic)
feat_read('file_mal_feat_1.csv')
feat_read('file_ben_feat_1.csv')
df_fet = pd.DataFrame(feature)
print(df_fet)



# Getting onegrams  
vector = CountVectorizer(ngram_range =(1, 1),lowercase = 'F')
val = vector.fit_transform(api_all_x)  
features = (vector.get_feature_names()) 

# Applying TFIDF 
# You can still get n-grams here 
vector_Tfidr = TfidfVectorizer(ngram_range = (1, 1),lowercase = 'F') 
val = vector_Tfidr.fit_transform(api_all_x) 
scores = (val.toarray()) 

sums = val.sum(axis = 0) 
data1 = [] 
for col, term in enumerate(features): 
    data1.append( (term, sums[0, col] )) 
rank = pd.DataFrame(data1, columns = ['term', 'rank']) 
wd = (rank.sort_values('rank', ascending = False)) 
print ("\n\nWords : \n", wd.head(7)) 


top120 = []
cnt = 0
for idx in wd.index:
    if cnt < 120:
        top120.append(wd['term'][idx])
        cnt += 1
    
# print(top120)
df_top120 = pd.DataFrame(top120)
# print(df_top120)
df_top120.to_csv(r'file_top_120.csv',index=False)
#     print(idx)

# print(top120)
