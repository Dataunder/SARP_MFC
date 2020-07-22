
// SARP_MFCDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "SARP_MFC.h"
#include "SARP_MFCDlg.h"
#include "afxdialogex.h"
#include "winsock2.h" 
#include "iphlpapi.h"  
#include "pcap.h" 
#include <windows.h>
#include <ws2ipdef.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


pcap_if_t* Dev, * allDevs;
pcap_t* currentOpenDev;
CString str;
PIP_ADAPTER_INFO pAdapterInf = 0;
PIP_ADAPTER_INFO pAdapter = 0;
PIP_ADAPTER_INFO SelectedAdapter = 0;
ULONG uBuf = 0;
DWORD opinf;

void TransCS2char(u_char ip[], CString tem);
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSARPMFCDlg 对话框



CSARPMFCDlg::CSARPMFCDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SARP_MFC_DIALOG, pParent)
	, V_DES_IP(_T(""))
	, R_Str(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSARPMFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_GETDEV_INF, dev_inf);
	DDX_Control(pDX, IDC_GETINF_BUT, GETINF_BUT);
	DDX_Control(pDX, IDC_SRC_IP, SRC_IP);
	DDX_Control(pDX, IDC_SRC_MAC, SRC_MAC);
	DDX_Control(pDX, IDC_DES_IP, DES_IP);
	DDX_Control(pDX, IDC_DES_MAC, DES_MAC);
	DDX_Control(pDX, IDC_SEND_INF, SEND_INF);
	DDX_Control(pDX, IDC_SEND_BUT, SEND_BUT);
	DDX_Text(pDX, IDC_DES_IP, V_DES_IP);
}

BEGIN_MESSAGE_MAP(CSARPMFCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_GETINF_BUT, &CSARPMFCDlg::OnBnClickedGetinfBut)
	ON_BN_CLICKED(IDC_SEND_BUT, &CSARPMFCDlg::OnBnClickedSendBut)
END_MESSAGE_MAP()


// CSARPMFCDlg 消息处理程序

BOOL CSARPMFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	opinf = GetAdaptersInfo(pAdapter, &uBuf);
	if (opinf == ERROR_BUFFER_OVERFLOW)
	{
		pAdapter = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, uBuf);//获取本地所有适配器并赋值
		pAdapterInf = pAdapter;	//将适配器信息赋值，防止接下来出现错误
		opinf = GetAdaptersInfo(pAdapter, &uBuf);	//获取本地网络信息，并赋值返回值
		if (opinf == ERROR_SUCCESS) 
		{
			while (pAdapterInf)//当适配器信息不空
			{
				dev_inf.AddString(pAdapterInf->Description);	//添加适配器信息至ComboBox中
				pAdapterInf = pAdapterInf->Next;	//继续下一个适配器
			}
		}
	}
	SendThread = NULL;

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSARPMFCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSARPMFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		//CDialogEx::OnPaint();
		CPaintDC   dc(this);
		CRect rect;
		GetClientRect(&rect);
		CDC   dcMem;
		dcMem.CreateCompatibleDC(&dc);
		CBitmap   bmpBackground;
		bmpBackground.LoadBitmap(IDB_BITMAP1);  //对话框的背景图片  

		BITMAP   bitmap;
		bmpBackground.GetBitmap(&bitmap);
		CBitmap* pbmpOld = dcMem.SelectObject(&bmpBackground);
		dc.StretchBlt(0, 0, rect.Width(), rect.Height(), &dcMem, 0, 0, bitmap.bmWidth, bitmap.bmHeight, SRCCOPY);
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSARPMFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}





void CSARPMFCDlg::OnBnClickedGetinfBut()
{
	// TODO: 在此添加控件通知处理程序代码
	CString selectedItem;		//用于存储当前选择的适配器名称
	dev_inf.GetLBText(dev_inf.GetCurSel(), selectedItem);	//赋值

	SelectedAdapter = pAdapter;			//定义选择的适配器为所有适配器信息
	while (SelectedAdapter->Description != selectedItem)	//执行循环，若当前适配器信息与所选择不符，则继续循环
	{
		SelectedAdapter = SelectedAdapter->Next;	
	}


	GetLocalDeviceInf();//输出并打印本地信息

}

void CSARPMFCDlg::GetLocalDeviceInf()
{
	SRC_IP.SetWindowTextA(SelectedAdapter->IpAddressList.IpAddress.String);			//将ID为SRC_IP的控件设置文本为获取的适配器中的信息
	str.Format("%02x-%02x-%02x-%02x-%02x-%02x",
		SelectedAdapter->Address[0],
		SelectedAdapter->Address[1],
		SelectedAdapter->Address[2],
		SelectedAdapter->Address[3],
		SelectedAdapter->Address[4],
		SelectedAdapter->Address[5]
	);
	SRC_MAC.SetWindowTextA(str);	//将ID为SRC_MAC的控件设置文本为获取的适配器中的mac信息

	DES_MAC.SetWindowTextA("00-00-00-00-00-00");	//将目的MAC设置为0x00


}



DWORD WINAPI SendArp(LPVOID lpParameter)
{
	CSARPMFCDlg* cdlg = (CSARPMFCDlg*)lpParameter;

	char errBuf[PCAP_ERRBUF_SIZE];

	pcap_findalldevs(&allDevs, errBuf);

	CString a = SelectedAdapter->AdapterName;	//将IP Helper的适配器名称存储在a字符串中

	CString subfromIpHelper = a.Mid(a.ReverseFind('{') + 1, 4);		//截取最后一个'{'出现后面4位字符串作为象征量

	//遍历打开的设备寻找与IP Helper中一致的设备
	for (Dev = allDevs; Dev; Dev = Dev->next) 
	{
		a = Dev->name;
		CString subfromWinpcap = a.Mid(a.ReverseFind('{') + 1, 4);	//截取最后一个'{'出现后面4位字符串作为象征量
		if (subfromWinpcap == subfromIpHelper)	//如果两个获取得设备象征量相同，说明打开的设备一致
		{
			break;
		}
	}

	if ((currentOpenDev = pcap_open(Dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errBuf)) == NULL)
	{
		return 0;
	}

	
	ArpPacket ap;
	u_char sendbuf[60];			//发送的数据包

	//基本内容的赋值
	ap.EthType = htons(ETH_ARP);
	ap.HardwareType = htons(ARP_HARDWARE);
	ap.ProtocolType = htons(ETH_IP);
	ap.HardwareLen = 6;
	ap.ProtocolLen = 4;
	ap.OpCode = htons(ARP_REQUEST);

	//将物理层的MAC设为0XFF表示广播，将数据链路层的设为0X00表示未知
	for (int i = 0; i < 6; i++)
	{
		ap.Des_Mac[i] = 0xff;
		ap.des_mac[i] = 0;
	}

	for (int i = 0; i < 6; i++)
	{
		ap.Src_Mac[i]= SelectedAdapter->Address[i];
		ap.src_mac[i]= SelectedAdapter->Address[i];
	}
	
/*
	cdlg->DES_IP.GetWindowText(a);

	int temp1 = a.Find('.');
	int temp2 = a.Find('.', temp1 + 1);
	int temp3 = a.Find('.', temp2 + 1);

	CString sub = a.Mid(0, temp1);
	CString sub1 = a.Mid(temp1+1, temp2-temp1-1);
	CString sub2 = a.Mid(temp2+1, temp3-temp2-1);
	CString sub3 = a.Mid(a.ReverseFind('.') + 1, 3);

	ap.des_ip[0] = atoi((LPCTSTR)sub);
	ap.des_ip[1] = atoi((LPCTSTR)sub1);
	ap.des_ip[2] = atoi((LPCTSTR)sub2);
	ap.des_ip[3] = atoi((LPCTSTR)sub3);
*/
	
	CString tem_d;

	//获取DES_IP框中的文本信息并将其写入定义的字符串中
	cdlg->DES_IP.GetWindowText(tem_d);

	//调用函数转化格式
	TransCS2char(ap.des_ip, tem_d);

	//CString src_ip=SelectedAdapter->IpAddressList.IpAddress.String;
	CString src_ip;

	//获取SRC_IP框中的文本信息并将其写入定义的字符串中
	cdlg->SRC_IP.GetWindowText(src_ip);

	//调用函数转化格式
	TransCS2char(ap.src_ip, src_ip);

	memset(ap.data, 0, 18);

	//将ap结构体赋值给发送报文字符串
	memset(&sendbuf, 0, sizeof(sendbuf));
	memcpy(&sendbuf, (unsigned char*)&ap, sizeof(ap));

	if (pcap_sendpacket(currentOpenDev, sendbuf, sizeof(sendbuf))==0)
	{
		cdlg->SEND_INF.SetWindowTextA("发送成功！");//发送报文成功时，在指定的编辑框内进行反馈
		return 1;
	}

	return 0;

}




void TransCS2char(u_char ip[], CString tem)
{
	CString sub[4];
	int temp1 = tem.Find('.');	//找到字符串中第一个出现'.'的索引	
	int temp2 = tem.Find('.', temp1 + 1);	//找到字符串中第二个出现'.'的索引
	int temp3 = tem.Find('.', temp2 + 1);	//找到字符串中第三个出现'.'的索引

	sub[0] = tem.Mid(0, temp1);		//将IP字符串第一个'.'前的字符分离
	sub[1] = tem.Mid(temp1 + 1, temp2 - temp1 - 1);	//将IP字符串第二个'.'前的字符分离
	sub[2] = tem.Mid(temp2 + 1, temp3 - temp2 - 1);	//将IP字符串第三个'.'前的字符分离
	sub[3] = tem.Mid(tem.ReverseFind('.') + 1, 3);	//将IP字符串第三个'.'后的字符分离

	for (int i = 0; i < 4; i++)
	{
		ip[i]= atoi((LPCTSTR)sub[i]);//循环赋值语句
	}

}

void CSARPMFCDlg::OnBnClickedSendBut()
{
	// TODO: 在此添加控件通知处理程序代码
	if (SelectedAdapter == 0)
	{
		MessageBox("请先选择设备");
	}
	else
	{
		if (SendThread == NULL)
		{
			SendThread = CreateThread(NULL, 0, SendArp, this, 0, NULL);
			SendThread = NULL;
		}
	}
}
