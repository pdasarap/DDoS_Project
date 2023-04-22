# DDoS_Project
Instructions on how to run the project - 

- Install Python
- Install Microsoft Visual C++ build tools 
- In python install netifaces package version 0.11.0, pyshark version 0.4.5

Steps to Run in the Python Environment - 

1) Run the python file - DDoSAttackDetection.py
      command ->  python DDoSAttackDetection.py
2) System will display a menu <br/>
     1) Run the Packet Sniffer 
			- to sniff network traffic based on the interface selected.
			-Then the program asks you to choose the network interface you want to collect information from.
				Choose the VMWare Network Adapter VMnet1.<br/>


     2) Collect Training Data  
			- to Preprocess the network data and create a training data set.
			- Then the program asks you to choose the network interface you want to collect information from.
				Choose the VMWare Network Adapter VMnet1. 
			- Training data is collected into Data.csv file.<br/>
			
     3) Train the ANN model    
			- Run the MLP Classifier algorithm on the training data.
			- Enter the name of training data file - 'Data.csv' 
			- System asks if you want to load any already existing model - select y or n 
			- if you select 'y' - then enter the name of the model - i.e. 'Model_test.sav' (this file is present in the project zip folder)
			- if you select 'n' - then a new model is trained and the performance metrics (confusion matrix, precision, recall)
						    of the model is displayed. You can save the model after this by giibng input as 'y' 
						    and name the model with .sav extension. <br/>

     4) Testing the ANN model  
			- Test the model using live network data.
			- Then the program asks you to choose the network interface you want to collect information from.
				Choose the VMWare Network Adapter VMnet1. 
			- Enter the name of model - give input as 'Model_test.sav'
			- The program will keep running until DDoS attack is deteted unless stopped explicitly.
			- Time of attack gets displayed on console and log file. 
			- The results are maintained in a log file - 'log.txt'<br/>

	   5) Exit
			- To end the program.



