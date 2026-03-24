using System;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    const int SCARD_SCOPE_USER = 0;
    const int SCARD_SHARE_SHARED = 2;
    const int SCARD_PROTOCOL_T1 = 2;

    static readonly IntPtr SCARD_PCI_T1 = new IntPtr(1);

    [DllImport("winscard.dll")]
    static extern int SCardEstablishContext(int dwScope, IntPtr r1, IntPtr r2, out IntPtr hContext);

    [DllImport("winscard.dll")]
    static extern int SCardListReaders(IntPtr hContext, byte[] groups, byte[] readers, ref int size);

    [DllImport("winscard.dll")]
    static extern int SCardConnect(IntPtr hContext, string readerName, int shareMode, int preferredProtocols, out IntPtr hCard, out int activeProtocol);

    [DllImport("winscard.dll")]
    static extern int SCardTransmit(IntPtr hCard, IntPtr sendPci, byte[] sendBuffer, int sendLength,
                                    IntPtr recvPci, byte[] recvBuffer, ref int recvLength);

    [DllImport("winscard.dll")]
    static extern int SCardDisconnect(IntPtr hCard, int disposition);

    static void Main()
    {
        IntPtr context;
        SCardEstablishContext(SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out context);

        int size = 0;
        SCardListReaders(context, null, null, ref size);

        byte[] readersBuf = new byte[size];
        SCardListReaders(context, null, readersBuf, ref size);

        string readerName = Encoding.ASCII.GetString(readersBuf).Split('\0')[0];
        Console.WriteLine("Reader: " + readerName);

        IntPtr card;
        int protocol;
        SCardConnect(context, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, out card, out protocol);

        // -------------------------
        // ① ポーリング（IDm取得）
        // -------------------------
        byte[] polling = new byte[]
        {
            0xFF,0x00,0x00,0x00,0x04,
            0xD4,0x4A,0x01,0x00
        };

        byte[] recv = new byte[256];
        int recvLen = recv.Length;

        SCardTransmit(card, SCARD_PCI_T1, polling, polling.Length, IntPtr.Zero, recv, ref recvLen);

        byte[] idm = new byte[8];
        Array.Copy(recv, 17, idm, 0, 8);

        Console.WriteLine("IDm: " + BitConverter.ToString(idm));

        // -------------------------
        // ② 書き込みデータ
        // -------------------------
        byte[] writeData = new byte[16];
        for (int i = 0; i < 16; i++) writeData[i] = (byte)i;

        // -------------------------
        // ③ FeliCa Writeコマンド
        // -------------------------
        byte[] felicaCmd = new byte[1 + 1 + 8 + 1 + 2 + 1 + 2 + 16];

        int idx = 0;
        felicaCmd[idx++] = (byte)felicaCmd.Length;
        felicaCmd[idx++] = 0x08; // Write Without Encryption

        Array.Copy(idm, 0, felicaCmd, idx, 8);
        idx += 8;

        felicaCmd[idx++] = 0x01; // サービス数
        felicaCmd[idx++] = 0x09; // サービスコード(L)
        felicaCmd[idx++] = 0x00; // サービスコード(H)

        felicaCmd[idx++] = 0x01; // ブロック数
        felicaCmd[idx++] = 0x80; // 2バイト指定
        felicaCmd[idx++] = 0x00; // ブロック番号

        Array.Copy(writeData, 0, felicaCmd, idx, 16);

        // -------------------------
        // ④ APDUラップ
        // -------------------------
        byte[] apdu = new byte[5 + felicaCmd.Length];
        apdu[0] = 0xFF;
        apdu[1] = 0x00;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = (byte)felicaCmd.Length;

        Array.Copy(felicaCmd, 0, apdu, 5, felicaCmd.Length);

        recvLen = recv.Length;

        var result = SCardTransmit(card, SCARD_PCI_T1, apdu, apdu.Length, IntPtr.Zero, recv, ref recvLen);

        Console.WriteLine("Write result: " + result);
        Console.WriteLine("Response: " + BitConverter.ToString(recv, 0, recvLen));

        SCardDisconnect(card, 0);

        Console.WriteLine("完了");
    }
}
