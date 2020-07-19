
// SARP_MFCDlg.h: 头文件
//

#pragma once
#include<pcap.h>
#include "iphlpapi.h"
#include "winsock2.h"
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答


#pragma pack(1)
struct ArpPacket
{
	u_char Des_Mac[6];    //目的MAC地址 
	u_char Src_Mac[6];   //源MAC地址 
	u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
	unsigned short HardwareType;   //硬件类型
	unsigned short ProtocolType;   //协议类型
	unsigned char HardwareLen;   //硬件地址长度
	unsigned char ProtocolLen;   //协议地址长度
	unsigned short OpCode;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char src_mac[6];   //源MAC地址
	u_char src_ip[4];   //源IP地址
	u_char des_mac[6];   //目的MAC地址
	u_char des_ip[4];   //目的IP地址

	u_char data[18];
};

// CSARPMFCDlg 对话框
class CSARPMFCDlg : public CDialogEx
{
// 构造
public:
	CSARPMFCDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SARP_MFC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	HANDLE SendThread;
	HANDLE RecThread;
	afx_msg void OnBnClickedGetinfBut();
	CComboBox dev_inf;
	afx_msg void GetLocalDeviceInf();
	CButton GETINF_BUT;
	CEdit SRC_IP;
	CEdit SRC_MAC;
	CEdit DES_IP;
	CEdit DES_MAC;
	CEdit SEND_INF;
	CButton SEND_BUT;
	CString V_DES_IP;
	afx_msg void OnBnClickedSendBut();
	CString R_Str;
};
