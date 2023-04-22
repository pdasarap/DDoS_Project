import winreg  # to use windows registry to ID guids given by netifaces
import netifaces  # used to identify network interfaces and return corresponding guid
import pickle
import csv
import pyshark  # tshark wrapper used to capture and parse packets
import time
import datetime
import pandas
from timeit import default_timer as timer
from sklearn.preprocessing import LabelEncoder


def main():
    print(__doc__)
    interface = netifaces.interfaces()
    mlp_test = 0
    allowed_IP = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']

    def get_ip_layer(packet):  # determine if a packet is ipv4 or ipv6
        for layer in packet.layers:
            if layer._layer_name == 'ip':
                return 4
            elif layer._layer_name == 'ipv6':
                return 6

    def packet_info(
            cap):  # Goes through each packet in capture or live_capture, displays various information about each packet
        start_time = time.time()
        try:
            i = 1
            for pkt in cap:
                i += 1
                try:
                    if pkt.highest_layer != 'ARP':
                        ip = None
                        ip_layer = get_ip_layer(pkt)
                        if ip_layer == 4:
                            ip = pkt.ip
                        elif ip_layer == 6:
                            ip = pkt.ipv6
                        print('Packet %d' % i)
                        print(pkt.highest_layer)
                        print(pkt.transport_layer)
                        print('Time', time.strftime("%Y-%m-%d %H:%M:%S"))
                        print('Layer: ipv%d' % get_ip_layer(pkt))
                        print('Source IP:', ip.src)
                        print('Destination IP:', ip.dst)
                        print('Length: ', pkt.length)
                        try:
                            print('Source Port', pkt[pkt.transport_layer].srcport)
                            print('Destination Port', pkt[pkt.transport_layer].dstport)
                        except AttributeError:
                            print('Source Port: ', 0)
                            print('Destination Port: ', 0)
                        print(i / (time.time() - start_time))
                        print('')
                    else:
                        arp = pkt.arp
                        print(pkt.highest_layer)
                        print(pkt.transport_layer)
                        print('Layer: ipv4')
                        print('Time', time.strftime("%Y-%m-%d %H:%M:%S"))
                        print('Source IP: ', arp.src_proto_ipv4)
                        print('Destination IP: ', arp.dst_proto_ipv4)
                        print('Length: ', pkt.length)
                        print('Source Port: ', 0)
                        print('Destination Port: ', 0)
                        print(i / (time.time() - start_time))
                        print()
                except (AttributeError, UnboundLocalError, TypeError) as e:
                    pass
            return
        except KeyboardInterrupt:
            pass

    def csv_collect(
            capture):  # creates/rewrites header row - goes through packets, writing a row to the csv for each packet
        start_time = time.time()
        with open('Data.csv', 'w', newline='') as csv_data:
            file_write = csv.writer(csv_data, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            file_write.writerow(
                ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                 'Packet Length', 'Packets/Time', 'target'])
            i = 0
            for packet in capture:
                try:
                    if packet.highest_layer != 'ARP':
                        ip = None
                        ip_layer = get_ip_layer(packet)
                        if ip_layer == 4:
                            ip = packet.ip
                            ipv = 0
                            if packet.transport_layer is None:
                                transport_layer = 'None'
                            else:
                                transport_layer = packet.transport_layer
                        elif ip_layer == 6:
                            ip = packet.ipv6
                            ipv = 1

                        try:
                            if ip.src not in allowed_IP:
                                ipcat = 1
                                target = 1
                            else:
                                ipcat = 0
                                target = 0
                            file_write.writerow([packet.highest_layer, transport_layer, ipcat, ip.dst,
                                                 packet[packet.transport_layer].srcport,
                                                 packet[packet.transport_layer].dstport,
                                                 packet.length, i / (time.time() - start_time), target])
                            i += 1
                        except AttributeError:
                            if ip.src not in allowed_IP:
                                ipcat = 1
                                target = 1
                            else:
                                ipcat = 0
                                target = 0
                            file_write.writerow(
                                [packet.highest_layer, transport_layer, ipcat, ip.dst, 0, 0,
                                 packet.length, i / (time.time() - start_time), target])
                            print("Time: ", time.time() - start_time)
                            print("Packets Collected:", i)
                            i += 1

                    else:
                        if packet.arp.src_proto_ipv4 not in allowed_IP:
                            ipcat = 1
                            target = 1
                        else:
                            ipcat = 0
                            target = 0
                        arp = packet.arp
                        file_write.writerow(
                            [packet.highest_layer, transport_layer, ipcat, arp.dst_proto_ipv4, 0, 0,
                             packet.length, i / (time.time() - start_time), target])
                        print("Time: ", time.time() - start_time)
                        print("Packets Collected:", i)
                        i += 1
                except (UnboundLocalError, AttributeError) as e:
                    pass

    def interface_names(
            interface_guids):  # Checks GUID of the network interfaces and converts it to identifiable format
        interface_name = interface_name = ['(unknown)' for i in range(len(interface_guids))]
        registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        registry_subkey = winreg.OpenKey(registry,
                                         r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        for i in range(len(interface_guids)):
            try:
                reg_subkey = winreg.OpenKey(registry_subkey, interface_guids[i] + r'\Connection')
                interface_name[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        return interface_name

    def LabelEncoding(data):  # Encodes categorical data and turns the categorical values into integer values

        data = pandas.read_csv('TestingData.csv', delimiter=',')
        cols = list(data.select_dtypes(include=['category', 'object']))

        label_encoder = LabelEncoder()
        for feature in cols:
            data[feature] = label_encoder.fit_transform(data[feature])

        return data

    def Load_model():  # loads a saved model to use for both training

        filename = input("Model to load?")
        loaded_model = pickle.load(open(filename, 'rb'))
        print(loaded_model.coefs_)
        print(loaded_model.loss_)

        return loaded_model

    def input_choice():
        for i, value in enumerate(interface_names(interface)):
            print(i, value)
        print('\n')
        interface_choice = input("Select interface of your choice: ")
        capture = pyshark.LiveCapture(interface=interface_choice)  # Sniff from interface
        capture.sniff_continuously(packet_count=None)
        return capture

    def MLP():

        csv_data = input("Enter the name of training data file: ")
        load = input("Do you want to load model? (y/n) ")
        if load == 'y':
            mlp = Load_model()

        else:
            from sklearn.neural_network import MLPClassifier
            mlp = MLPClassifier(hidden_layer_sizes=(100, 100), activation='logistic', max_iter=10, verbose=True,
                                tol=0.00000001, early_stopping=True,
                                shuffle=True)

        data = pandas.read_csv(csv_data, delimiter=',')
        data = LabelEncoding(data)

        X = data[
            ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port', 'Packet Length',
             'Packets/Time']]
        y = data['target']

        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
        X_train, X_test, y_train, y_test = train_test_split(X, y)

        start_time = timer()
        mlp.fit(X_train, y_train)
        end_time = timer()
        time_taken = end_time - start_time
        pred = mlp.predict(X_test)
        print("\nIteration: ", mlp.n_iter_, "\n")
        hostile = 0
        safe = 0
        for check in pred:
            if check == 1:
                hostile += 1
            else:
                safe += 1
        print("Number of Safe Packets: ", safe)
        print("Number of Hostile Packets: ", hostile)
        print("Time Elapsed:", time_taken)

        from sklearn.metrics import classification_report, confusion_matrix
        print("Confusion Matrix: ", "\n", confusion_matrix(y_test, pred), "\n")
        print("Classification Report: ", "\n", classification_report(y_test, pred), "\n")
        print("Model Coefficients (Weights): ", "\n", mlp.coefs_, "\n")
        print("Model Intercepts (Nodes): ", "\n", mlp.intercepts_, "\n")

        save = input("Do you want to save model? (y/n) ")
        if save == 'y':
            filename = input("Model Name for saving?: ")
            pickle.dump(mlp, open(filename, 'wb'))

    def MLP_Predict(capture, model_name, mlp_live):  # Used for real-time classification and not training

        data = pandas.read_csv('TestData.csv', delimiter=',')
        data = LiveLabelEncoding(data)
        print("Processing Data", "\n")
        print(data)
        X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                  'Packet Length', 'Packets/Time']]

        model_load = pickle.load(open(model_name, 'rb'))
        load_mlp = model_load
        pred = load_mlp.predict(X)

        hostile = 0
        safe = 0
        for check in pred:
            if check == 1:  # change to 0 to force ddos attack
                hostile += 1
            else:
                safe += 1
        print("Safe Packets: ", safe)
        print("Possible Hostile Packets: ", hostile)
        print(100 * hostile / (safe + hostile))
        print("\n")
        mlp_live += 1

        if hostile >= ((safe + hostile) / 2):
            log_writer = open('log.txt', 'a+')
            log_writer.write('Attack Detected at: ')
            log_writer.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            log_writer.write('\n')
            log_writer.write('Packets collected: ')
            log_writer.write(str(safe + hostile))
            log_writer.write('\n')
            return "Attack"
        else:
            log_writer = open('log.txt', 'a+')
            log_writer.write('Normal Activity Detected at: ')
            log_writer.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            log_writer.write('\n')
            log_writer.write('Packets collected: ')
            log_writer.write(str(safe + hostile))
            log_writer.write('\n \n')

            return mlp_live

    def test_data_collect(capture):  # creates/updates 'TestData.csv' by inserting each packet data into the file
        start_time = time.time()
        with open('TestData.csv', 'w', newline='') as csvfile:
            file_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            file_writer.writerow(['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                                 'Packet Length', 'Packets/Time'])

            i = 0
            start = timer()
            for packet in capture:
                end = timer()
                if (end - start < 30):
                    try:
                        if packet.highest_layer != 'ARP':
                            print("Packets Collected:", i)
                            if packet.highest_layer != 'ARP':
                                ip = None
                                ip_layer = get_ip_layer(packet)
                                if ip_layer == 4:
                                    ip = packet.ip
                                    # ipv = 0 # target test
                                    if packet.transport_layer == None:
                                        transport_layer = 'None'
                                    else:
                                        transport_layer = packet.transport_layer
                                elif ip_layer == 6:
                                    ip = packet.ipv6
                                    # ipv = 1 # target test
                                try:
                                    if ip.src not in allowed_IP:
                                        ipcat = 1
                                    else:
                                        ipcat = 0
                                    file_writer.writerow([packet.highest_layer, transport_layer, ipcat, ip.dst,
                                                         packet[packet.transport_layer].srcport,
                                                         packet[packet.transport_layer].dstport, packet.length,
                                                         i / (time.time() - start_time)])
                                    print("Time: ", time.time() - start_time)
                                    i += 1
                                except AttributeError:
                                    if ip.src not in allowed_IP:
                                        ipcat = 1
                                    else:
                                        ipcat = 0
                                    file_writer.writerow(
                                        [packet.highest_layer, transport_layer, ipcat, ip.dst, 0, 0, packet.length,
                                         i / (time.time() - start_time)])
                                    print("Time: ", time.time() - start_time)
                                    i += 1

                            else:
                                if packet.arp.src_proto_ipv4 not in allowed_IP:
                                    ipcat = 1
                                else:
                                    ipcat = 0
                                arp = packet.arp
                                file_writer.writerow(
                                    [packet.highest_layer, transport_layer, ipcat, arp.dst_proto_ipv4, 0, 0, packet.length,
                                     i / (time.time() - start_time)])
                                print("Time: ", time.time() - start_time)
                                i += 1
                    except (UnboundLocalError, AttributeError) as e:
                        pass
                else:
                    return

    def LiveLabelEncoding(data):  # same as LabelEncoding(), but use for realtime
        data = pandas.read_csv('TestData.csv', delimiter=',')
        columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
        print(columnsToEncode)
        le = LabelEncoder()
        for feature in columnsToEncode:
            try:
                data[feature] = le.fit_transform(data[feature])
                # print(data[feature])
            except:
                print('error ' + feature)
        return data

    def menu():  # Basic Menu
        choice = True
        test = True
        while choice:
            print("""
                1. Run the Packet Sniffer
                2. Collect train Data
                3. Training ANN Model
                4. Testing ANN Model
                5. Exit
                """)

            choice = input("What would you like to do? ")
            if choice == "1":
                capture = input_choice()
                packet_info(capture)
            elif choice == "2":
                capture = input_choice()
                print("Collecting training data : ")
                csv_collect(capture)
            elif choice == "3":
                MLP()
            elif choice == "4":
                capture = input_choice()
                model = input("Enter the model name: ")
                try:
                    while test:
                        test_data_collect(capture)
                        if MLP_Predict(capture, model,mlp_test) == "Attack":
                            test = False
                            print("DDoS Attack Detected! Time: ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
                            MLP_Predict(capture, model, mlp_test) == 0
                except KeyboardInterrupt:
                    pass

            elif choice == "5":
                break

    menu()


main()
