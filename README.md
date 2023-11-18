# lorawan_note_send

This project mainly simulates a gateway and devices in a LoRaWAN network communication environment, with ChirpStack serving as the network server. A local UDP client is used to handle communication with the ChirpStack network. The general workflow is as follows:

[1]First, register a gateway and a device in ChirpStack, but both are inactive.

[2]Use a local UDP client to send PULL_DATA messages to activate the gateway on ChirpStack.

[3]After activation, use the same local client to send a JOIN-REQUEST message to the gateway. When the gateway receives it, ChirpStack will activate the registered device, allowing it to receive messages.

[4]Send data packets to the device through the local UDP client.

[5]You can observe the device receiving data packets on the ChirpStack interface.

## pull_data
python main.py pull


![1](images/1.png)

## join_request
python main.py join -n / python main.py join


![2](images/2.png)

## send_data
python main.py app test


![3](images/3.png)

![4](images/4.png)

![5](images/5.png)

![6](images/6.png)

![7](images/7.png)
