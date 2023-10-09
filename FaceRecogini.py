# import os
import base64
# rootdir = 'C:/Users/USER/Desktop/sikeimp/sibc/dataset2'
# path='C:/Users/USER/Desktop/sikeimp/sibc/dataset2'

# with open("sibc\dataset2\Andre_Agassi_0001.jpg", "rb") as image2string:
#     converted_string = base64.b64encode(image2string.read())
# print(converted_string)
  
# with open('sibc\dataset2\Andre_Agassi_0001.bin', "wb") as file:
#     file.write(converted_string)
# for file in os.listdir(rootdir):
#         print(file)
#         with open(file, "rb") as image:
#              b64string = base64.b64encode(image.read())
#         # value=str(os.path.splitext(file)[0])
#         # value+='.bin'
#         # with open(value,"wb") as itr:
#         #     itr.write(value)
import os
rootdir = 'C:/Users/USER/Desktop/sikeimp/sibc/dataset2'

for subdir, dirs, files in os.walk(rootdir):
    for file in files:
        
        with open(os.path.join(subdir, file), "rb") as image2string:
            converted_string = base64.b64encode(image2string.read())
        
        value=str(os.path.join(subdir,file))
        # print(value[:-4])
        binary=value[:-4]
        binary+=".bin"
        print(binary)        
        with open(binary, "wb") as file:
            file.write(converted_string)
 