# pip3 install pycryptodome
from Crypto.Cipher import AES

# 模拟服务器
class AESServer:
    def __init__(self):
        key = b'Sixteen byte key'
        self.e_cipher = AES.new(key, AES.MODE_CBC)
        self.d_cipher = AES.new(key, AES.MODE_CBC, self.e_cipher.iv)
    
    # 用于模拟给客户端返回密文，例如session值
    def get_ciphertext(self):
        data = b'hello, padding oracle attack!'
        return self._encrypt(data)
    
    # 用于模拟处理客户端的密文输入，但是不会返回明文
    # 服务器在遇到正确的数据时返回OK，但是遇到畸形数据时，在解密过程会产生异常
    def process_ciphertext(self, ciphertext):
        plaintext = self._decrypt(ciphertext)
        return True

    # 以下为内部函数

    # 加密函数，加密前先填充padding
    def _encrypt(self, data):
        data = self._pad(data)
        ciphertext = self.e_cipher.encrypt(data)
        return ciphertext
    
    # 解密函数，解密后去除padding，这里有可能会产生异常
    def _decrypt(self, data):
        plaintext = self.d_cipher.decrypt(data)
        plaintext = self._unpad(plaintext)
        return plaintext

    # 填充padding
    def _pad(self, data):
        pad_len = (16-len(data)) % 16
        if pad_len == 0:
            pad_len = 16
        data = data + bytes([pad_len] * pad_len)
        return data

    # 去除padding
    def _unpad(self, data):
        pad_len = data[-1]
        if 0 < pad_len <= 16:
            for i in data[-pad_len:]:
                if i != pad_len:
                    raise Exception('invalid padding')
            #print('pad_len', pad_len)
            return data[:-pad_len]
        else:
            raise Exception('invalid padding len')

class PadBuster:
    def __init__(self):
        self.aes_server = AESServer()
    
    def bust(self):
        # 客户端从服务器获取加密后的session
        ciphertext = self.aes_server.get_ciphertext()
        print('[*] get ciphertext', ciphertext)

        # 假设这里可以知道加密的初始向量（如果没有这个值，则不能解密第一块数据）
        prev_block = self.aes_server.e_cipher.iv

        # 按块处理
        for i in range(int(len(ciphertext)/16)):
            block = ciphertext[i*16:i*16+16]
            # 根据padding oracle计算解密过程的中间值
            intermediary = self._get_intermediary(block)
            # 根据cbc算法，将上一块密文和当前中间值进行异或得到明文
            plaintext = bytearray([prev_block[i]^intermediary[i] for i in range(16)])
            print('[+] block %d plaintext: %s' % (i, plaintext))
            prev_block = block

    # 根据padding oracle计算解密过程的中间值
    def _get_intermediary(self, block):
        # 初始化初始向量为全0
        iv = [0] * 16
        # 初始化中间值为全0
        intermediary = [0] * 16

        # 从最后一个字节往前依次计算
        for i in range(16):
            # 根据已经计算出来的中间值重新初始化初始向量，例如i=1时，可以计算初始向量的最后一个字节
            # 例如已经计算出最后两个字节的中间值，下一次计算应该使得解密后的明文的最后三个字节都为0x03
            # 由于最后两个字节的中间值已经计算出来，因此根据CBC解密算法，中间值的后两个字节异或0x03后即为初始向量的最后两个字节
            # 只需要暴力破解倒数第三个字节即可
            for j in range(i):
                iv[15 - j] = intermediary[15 - j] ^ (i + 1)

            # 开始暴力破解第15-i个字节的中间值
            for v in range(256):
                iv[15 - i] = v
                # 将初始向量拼接密文块作为向服务器提交的密文数据
                ciphertext = bytes(iv) + block
                try:
                    # 向服务器提交构造好的密文，如果解密出来的padding有问题，这里会报异常
                    self.aes_server.process_ciphertext(ciphertext)
                    # 如果没有报异常说明说明构造的密文被正确解密了，且解密的明文为i+1,如果i=2，明文为0x3
                    # 将初始向量对应字节和和0x3异或即可得到中间值
                    intermediary[15 - i] = v ^ (i + 1)
                    #continue
                except:
                    pass
        # print(bytearray(intermediary).hex())
        return intermediary

padBuster = PadBuster()
padBuster.bust()