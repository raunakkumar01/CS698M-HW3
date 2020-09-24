# -*- coding: utf-8 -*-
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
from keras.models import Sequential
from keras.layers import Dense
def preprocessData():
	# USAGE
	#trX, trY, teX, teY = preprocessData();

	# Load data
	a = pd.read_excel("DynamicAnalysis.xlt")#"StaticAnalysis_PEH_trimmed.xlt")#"DynamicAnalysis_NW.xlt")
	
	# Extract  features and labels
	x = np.array(a.iloc[:, 2:16])#[:,2:153])
	
	x=np.delete(x,12,1)
	y_o = np.array(a.iloc[:,1])
	x = pd.DataFrame(x).fillna(0)

	y = []
	for inp in y_o:
		if(inp == 'M'):
			y.append(1)
		else:
			y.append(0)
	# print(x)#("x:"+x+"\ny:"SS+y)
	
	# Separate Train-Test data
	xTrain, xTest, yTrain, yTest = train_test_split(x, y, test_size = 0.25, random_state = np.random.randint(10))
	
	return xTrain, xTest, yTrain, yTest 

# Load and preprocess data
train_x, test_x, train_y, test_y = preprocessData()


#Train  hyperparameter value
c_value = [0.00001,0.0001,0.001,0.01,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]

######### Decision tree #####################
clf = DecisionTreeClassifier()
clf = clf.fit(train_x,train_y)
y_pred = clf.predict(test_x)
print("DT ")
print("accuracy_score: ",accuracy_score(test_y,y_pred))
print("precision_score: ",precision_score(test_y,y_pred))
print('recall_score: ',recall_score(test_y,y_pred))
print(confusion_matrix(test_y, y_pred))
print("\n\n")
#############################################


######### Support vector machine ############
c = 20
# for c in c_value:
clf = SVC(C = c,gamma = "scale") # for new data @0.2 for final  now at 20
clf = clf.fit(train_x,train_y)
y_pred = clf.predict(test_x)
print("svm at C =:",c)
print("accuracy_score: ",accuracy_score(test_y,y_pred))
print("precision_score: ",precision_score(test_y,y_pred))
print('recall_score: ',recall_score(test_y,y_pred))
print(confusion_matrix(test_y, y_pred))
print("\n\n")
#############################################


######### Logistic regression ###############
c =0.0001
# for c in c_value:
clf = LogisticRegression(C = c, solver = "liblinear")#best at c =0.0001
clf = clf.fit(train_x,train_y)
y_pred = clf.predict(test_x)
print("Logistic regression at c:",c)
print("accuracy_score: ",accuracy_score(test_y,y_pred))
print("precision_score: ",precision_score(test_y,y_pred))
print('recall_score: ',recall_score(test_y,y_pred))
print(confusion_matrix(test_y, y_pred))
print("\n\n")
#############################################


# ########## KNN ##############################
c = 5
# for c in range(1,30):
clf = KNeighborsClassifier(n_neighbors = c) # best at c =1 @5 final
clf = clf.fit(train_x,train_y)
y_pred = clf.predict(test_x)
print("KNN  at:",c)
print("accuracy_score: ",accuracy_score(test_y,y_pred))
print("precision_score: ",precision_score(test_y,y_pred))
print('recall_score: ',recall_score(test_y,y_pred))
print(confusion_matrix(test_y, y_pred))
print("\n\n")
# #############################################


################ RF ##################
from sklearn.ensemble import RandomForestClassifier

clf_rf = RandomForestClassifier()

clf_rf.fit(train_x,train_y)
y_pred = clf_rf.predict(test_x)

print("Analysis using RandomForestClassifier Tree")
print("accuracy_score: ",accuracy_score(test_y,y_pred))
print("precision_score: ",precision_score(test_y,y_pred))
print('recall_score: ',recall_score(test_y,y_pred))
print(confusion_matrix(test_y, y_pred))
print("\n\n")
################ RF ##################

# #########                           Save the required objects                          ############
# # Save the best model
filename = "model"
joblib.dump(clf_rf, filename)
