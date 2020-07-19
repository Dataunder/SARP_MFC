
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
PIP_ADAPTER_INFO pAdapter = 0;
PIP_ADAPTER_INFO currentSlectedAdapter = 0;
ULONG uBuf = 0;
DWORD dwRet;

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
	dwRet = GetAdaptersInfo(pAdapter, &uBuf);
	if (dwRet == ERROR_BUFFER_OVERFLOW)
	{
		pAdapter = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, uBuf);
		dwRet = GetAdaptersInfo(pAdapter, &uBuf);
		if (dwRet == ERROR_SUCCESS) {
			dev_inf.AddString(pAdapter->Description);
			dev_inf.AddString(pAdapter->Next->Description);
		}
	}
	SendThread = NULL;
	RecThread = NULL;

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
	CString selectedItem;
	dev_inf.GetLBText(dev_inf.GetCurSel(), selectedItem);
	currentSlectedAdapter = pAdapter;
	while (currentSlectedAdapter->Description != selectedItem)
	{
		currentSlectedAdapter = currentSlectedAdapter->Next;
	}


	GetLocalDeviceInf();//输出并打印本地信息

}

void CSARPMFCDlg::GetLocalDeviceInf()
{
	SRC_IP.SetWindowTextA(currentSlectedAdapter->IpAddressList.IpAddress.String);
	str.Format("%02x-%02x-%02x-%02x-%02x-%02x",
		currentSlectedAdapter->Address[0],
		currentSlectedAdapter->Address[1],
		currentSlectedAdapter->Address[2],
		currentSlectedAdapter->Address[3],
		currentSlectedAdapter->Address[4],
		currentSlectedAdapter->Address[5]
	);
	SRC_MAC.SetWindowTextA(str);

	DES_MAC.SetWindowTextA("00-00-00-00-00-00");

}



DWORD WINAPI SendArp(LPVOID lpParameter)
{
	CSARPMFCDlg* cdlg = (CSARPMFCDlg*)lpParameter;
	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&allDevs, errBuf);

	CString a = currentSlectedAdapter->AdapterName;

	CString subfromIpHelper = a.Mid(a.ReverseFind('{') + 1, 4);
	for (Dev = allDevs; Dev; Dev = Dev->next) 
	{
		a = Dev->name;
		CString subfromWinpcap = a.Mid(a.ReverseFind('{') + 1, 4);
		if (subfromWinpcap == subfromIpHelper) 
		{
			break;
		}
	}

	if ((currentOpenDev = pcap_open(Dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errBuf)) == NULL)
	{
		return 0;
	}

	
	ArpPacket ap;
	u_char sendbuf[60];

	ap.EthType = htons(ETH_ARP);
	ap.HardwareType = htons(ARP_HARDWARE);
	ap.ProtocolType = htons(ETH_IP);
	ap.HardwareLen = 6;
	ap.ProtocolLen = 4;
	ap.OpCode = htons(ARP_REQUEST);

	for (int i = 0; i < 6; i++)
	{
		ap.Des_Mac[i] = 0xff;
		ap.des_mac[i] = 0;
	}

	for (int i = 0; i < 6; i++)
	{
		ap.Src_Mac[i]= currentSlectedAdapter->Address[i];
		ap.src_mac[i]= currentSlectedAdapter->Address[i];
	}
	

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

	CString src_ip=currentSlectedAdapter->IpAddressList.IpAddress.String;

	TransCS2char(ap.src_ip, src_ip);

	memset(ap.data, 0, 18);

	memset(&sendbuf, 0, sizeof(sendbuf));
	memcpy(&sendbuf, (unsigned char*)&ap, sizeof(ap));

	if (pcap_sendpacket(currentOpenDev, sendbuf, sizeof(sendbuf))==0)
	{
		cdlg->SEND_INF.SetWindowTextA("发送成功！");
	}

}




void TransCS2char(u_char ip[], CString tem)
{
	CString sub[4];
	int temp1 = tem.Find('.');
	int temp2 = tem.Find('.', temp1 + 1);
	int temp3 = tem.Find('.', temp2 + 1);

	sub[0] = tem.Mid(0, temp1);
	sub[1] = tem.Mid(temp1 + 1, temp2 - temp1 - 1);
	sub[2] = tem.Mid(temp2 + 1, temp3 - temp2 - 1);
	sub[3] = tem.Mid(tem.ReverseFind('.') + 1, 3);

	for (int i = 0; i < 4; i++)
	{
		ip[i]= atoi((LPCTSTR)sub[i]);
	}

}

void CSARPMFCDlg::OnBnClickedSendBut()
{
	// TODO: 在此添加控件通知处理程序代码
	if (currentSlectedAdapter == 0)
	{
		MessageBox("请先于左侧框内选择设备！");
	}
	else {
		if (SendThread == NULL)
		{
			SendThread = CreateThread(NULL, 0, SendArp, this, 0, NULL);
		}
		else 
		{
			ResumeThread(SendThread);
		}

	}
}
