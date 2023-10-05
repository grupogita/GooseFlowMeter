import numpy as np
import pandas as pd

import pickle

from sklearn import preprocessing

class ClassifierML:

	def __init__ (self):
		self.filename = '/home/santiagoguiral/Documents/udea/maestria/projects/cicgoose/gooseflowmeter/src/gooseflowmeter/ml_model.sav'
		self.loaded_model = pickle.load(open(self.filename, 'rb'))
		print(self.loaded_model)
		self.y_predicted = []
		self.y_actual = []

	def PrintResults (self):
		print(f'Y Actual {self.y_actual}')
		print(f'Y Predic {self.y_predicted}')
		print(f' Length: {len(self.y_actual)}')


	def CleanData (self, flow_data):
		df = pd.DataFrame.from_dict([flow_data])
		df.drop(columns = ['src_mac','dst_mac','appid','gocbRef','stNum','sqNum_Norm','timeAllowedtoLive','datSet','goID','test','confRev','ndsCom','numDatSetEntries','timestamp'], inplace=True)
		df.drop(columns = ['flow_pkts_s', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_median', 'flow_header_len', 'flow_iat_tot', 'pkt_size_avg', 'idle_std', 'flow_pkts_b_avg'], inplace=True)
		df.drop(columns=  ['pkt_len_std', 'pkt_len_var', 'flow_seg_size_min'],inplace=True)				

		target = df['flow_label']
		inputx = df.drop(columns = ['flow_label'])
		
		df_cols = list(inputx.columns)
		
		scaler = preprocessing.StandardScaler()
		#data_norm = scaler.fit_transform(inputx)	

		transformer = preprocessing.Normalizer()
		data_norm = transformer.fit_transform(inputx)

		robust = preprocessing.RobustScaler()
		#data_norm = robust.fit_transform(inputx)

		minmax = preprocessing.MinMaxScaler()
		#data_norm = robust.fit_transform(inputx)

		#data_norm = inputx

		data = pd.DataFrame(data_norm, columns= df_cols)

		if target.item() == 3:
			t = 1
			data.insert(len(df_cols), "flow_label", [t], True)
		else:
			t = 0
			data.insert(len(df_cols), "flow_label", [t], True)
		return data

	def MLClassify (self, df):
		#df = pd.DataFrame.from_dict([flow_data])
		
		target = df['flow_label']
		inputx = df.drop(columns = ['flow_label'])
		y_predicted = self.loaded_model.predict(inputx)
		y = target.item()		
		self.y_predicted.append(y_predicted[0])
		self.y_actual.append(y)
		
		print(f'Y Actual: {y}')
		print(f'Y Predicted: {y_predicted[0]}')
		return y_predicted
