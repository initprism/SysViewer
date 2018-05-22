#include <QTreeView>
#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QStackedWidget>
#include <QSplitter>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QListWidget>
#include <QFileDialog>
#include <QFile>
#include <QLabel>
#include <QHeaderView>
#include "PeLib\PeLib.h"
#include "HexLib\HexLib.h"
#include "peview.h"
#include "formatter.h"

PeView::PeView(QString filePath, QWidget *parent)
	: QWidget(parent)
{	
	// --------------------- load pefile & read headers ----------------------- //
	QString fileName = QFileInfo(filePath).fileName();
	unsigned int type = PeLib::getFileType(filePath.toLatin1().data()); //type of pefile
	PeLib::PeFile* pef;
	pef = PeLib::openPeFile(filePath.toLatin1().data());
	pef->readMzHeader();
	pef->readPeHeader();
	pef->readExportDirectory();
	pef->readImportDirectory();

	hex_f = new QFile();
	hex_f->setFileName(filePath);

	//dos header//
	const PeLib::MzHeader& mzh = pef->mzHeader();

	//nt header//
	const PeLib::PeHeaderT<32>& peh32 = static_cast<PeLib::PeFileT<32>&>(*pef).peHeader();
	const PeLib::PeHeaderT<64>& peh64 = static_cast<PeLib::PeFileT<64>&>(*pef).peHeader();
	const PeLib::ExportDirectory& exp = (*pef).expDir();
	const PeLib::ImportDirectory<32>& imp32 = static_cast<PeLib::PeFileT<32>&>(*pef).impDir();
	const PeLib::ImportDirectory<64>& imp64 = static_cast<PeLib::PeFileT<64>&>(*pef).impDir();

	// --------------------- pefile tree info ----------------------- //
	treeView = new QTreeView(this);
	standardModel = new QStandardItemModel;
	QStandardItem *rootNode = standardModel->invisibleRootItem();

	QStandardItem *FILE = new QStandardItem(fileName);
	QStandardItem *IMAGE_DOS_HEADER = new QStandardItem("IMAGE_DOS_HEDEAR");
	QStandardItem *DOS_STUB_PROGRAM = new QStandardItem("DOS_STUB_PROGRAM");
	QStandardItem *IMAGE_NT_HEADER = new QStandardItem("IMAGE_NT_HEADER");
	QStandardItem *SIGNATURE = new QStandardItem("Signature");
	QStandardItem *IMAGE_FILE_HEADER = new QStandardItem("IMAGE_FILE_HEADER");
	QStandardItem *IMAGE_OPTIONAL_HEADER = new QStandardItem("IMAGE_OPTIONAL_HEADER");
	QStandardItem *IMAGE_DATA_DIRECTORY = new QStandardItem("IMAGE_DATA_DIRECTORY");
	QStandardItem *SECTION_HEADER = new QStandardItem("Section Header");
	QStandardItem *SECTION_BODY = new QStandardItem("Section Body");
	QStandardItem *EXPORT_DIRECTORY = new QStandardItem("EXPORT_DIRECTORY");
	QStandardItem *IMPORT_DIRECTORY = new QStandardItem("IMPORT_DIRECTORY");

	rootNode->					appendRow(FILE);
	FILE->						appendRow(IMAGE_DOS_HEADER);
	FILE->						appendRow(DOS_STUB_PROGRAM);
	FILE->						appendRow(IMAGE_NT_HEADER);
	FILE->						appendRow(SECTION_HEADER);
	FILE->						appendRow(SECTION_BODY);
	FILE->						appendRow(EXPORT_DIRECTORY);
	FILE->						appendRow(IMPORT_DIRECTORY);
	IMAGE_NT_HEADER->			appendRow(SIGNATURE);
	IMAGE_NT_HEADER->			appendRow(IMAGE_FILE_HEADER);
	IMAGE_NT_HEADER->			appendRow(IMAGE_OPTIONAL_HEADER);
	IMAGE_OPTIONAL_HEADER->		appendRow(IMAGE_DATA_DIRECTORY);
	
	// section header & section body & export & import directory //
	switch (type) { // depends on the type of file.
		case PeLib::PEFILE32:
			for (int i = 0; i < peh32.getNumberOfSections(); i++) {
				SECTION_HEADER->appendRow(new QStandardItem(peh32.getSectionName(i).c_str()));
				SECTION_BODY->appendRow(new QStandardItem(peh32.getSectionName(i).c_str()));
			}

			for (unsigned int i = 0; i < imp32.getNumberOfFiles(PeLib::OLDDIR); i++) {
				IMPORT_DIRECTORY->appendRow(new QStandardItem(imp32.getFileName(i, PeLib::OLDDIR).c_str()));
			}
			numberOfSection = peh32.getNumberOfSections();
			break;
		case PeLib::PEFILE64:
			for (int i = 0; i < peh64.getNumberOfSections(); i++) {
				SECTION_HEADER->appendRow(new QStandardItem(peh64.getSectionName(i).c_str()));
				SECTION_BODY->appendRow(new QStandardItem(peh64.getSectionName(i).c_str()));
			}

			for (unsigned int i = 0; i < imp64.getNumberOfFiles(PeLib::OLDDIR); i++) {
				IMPORT_DIRECTORY->appendRow(new QStandardItem(imp64.getFileName(i, PeLib::OLDDIR).c_str()));
			}
			numberOfSection = peh64.getNumberOfSections();
			break;
	}


	treeView->setModel(standardModel);
	treeView->expandAll();

	// --------------------- stackedWidget info ----------------------- //
	//set image dos header stackwidget//
	QTableWidget* IMAGE_DOS_HEADER_s = new QTableWidget;

	IMAGE_DOS_HEADER_s->setRowCount(17 + 3 + 9);
	IMAGE_DOS_HEADER_s->setColumnCount(3);
	IMAGE_DOS_HEADER_s->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
	IMAGE_DOS_HEADER_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	IMAGE_DOS_HEADER_s->verticalHeader()->setVisible(false);
	IMAGE_DOS_HEADER_s->setShowGrid(false);
	IMAGE_DOS_HEADER_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	IMAGE_DOS_HEADER_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	IMAGE_DOS_HEADER_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	IMAGE_DOS_HEADER_s->setStyleSheet("font-size : 13px");

	setTableItem(IMAGE_DOS_HEADER_s, 0, "e_magic", toString(mzh.getMagicNumber()));
	setTableItem(IMAGE_DOS_HEADER_s, 1, "e_cblp", toString(mzh.getBytesOnLastPage()));
	setTableItem(IMAGE_DOS_HEADER_s, 2, "e_cp", toString(mzh.getPagesInFile()));
	setTableItem(IMAGE_DOS_HEADER_s, 3, "e_crlc", toString(mzh.getRelocations()));
	setTableItem(IMAGE_DOS_HEADER_s, 4, "e_cparhdr", toString(mzh.getSizeOfHeader()));
	setTableItem(IMAGE_DOS_HEADER_s, 5, "e_minalloc", toString(mzh.getMinExtraParagraphs()));
	setTableItem(IMAGE_DOS_HEADER_s, 6, "e_maxalloc", toString(mzh.getMaxExtraParagraphs()));
	setTableItem(IMAGE_DOS_HEADER_s, 7, "e_ss", toString(mzh.getSsValue()));
	setTableItem(IMAGE_DOS_HEADER_s, 8, "e_sp", toString(mzh.getSpValue()));
	setTableItem(IMAGE_DOS_HEADER_s, 9, "e_csum", toString(mzh.getChecksum()));
	setTableItem(IMAGE_DOS_HEADER_s, 10, "e_ip", toString(mzh.getIpValue()));
	setTableItem(IMAGE_DOS_HEADER_s, 11, "e_cs", toString(mzh.getCsValue()));
	setTableItem(IMAGE_DOS_HEADER_s, 12, "e_lfarlc", toString(mzh.getAddrOfRelocationTable()));
	setTableItem(IMAGE_DOS_HEADER_s, 13, "e_ovnovalue", toString(mzh.getOverlayNumber()));
	setTableItem(IMAGE_DOS_HEADER_s, 14, "e_oemid", toString(mzh.getOemIdentifier()));
	setTableItem(IMAGE_DOS_HEADER_s, 15, "e_oeminfo", toString(mzh.getOemInformation()));
	setTableItem(IMAGE_DOS_HEADER_s, 16, "e_lfanew", toString(mzh.getAddressOfPeHeader()));

	for (unsigned int i = 0; i <= 3; i++)
	{
		setTableItem(IMAGE_DOS_HEADER_s, 16 + i + 1, "e_res", toString(mzh.getReservedWords1(i)));
	}
	for (unsigned int i = 0; i <= 9; i++)
	{
		setTableItem(IMAGE_DOS_HEADER_s, 16 + 3 + i + 1, "e_res2", toString(mzh.getReservedWords2(i)));
	}
	
	//set dos stub code, this is hex codes with hexlib//
	QWidget* DOS_STUB_PROGRAM_s =		new QWidget;

	HexLib::HexLib *dos_stub_hex = new HexLib::HexLib(this);
	dos_stub_hex->setData(*hex_f);
	dos_stub_hex->setData(dos_stub_hex->data(40, mzh.getAddressOfPeHeader() - 40));

	QHBoxLayout *dos_stub_hbox = new QHBoxLayout(this);
	dos_stub_hbox->addWidget(dos_stub_hex);
	dos_stub_hbox->setContentsMargins(0, 0, 0, 0);

	DOS_STUB_PROGRAM_s->setLayout(dos_stub_hbox);

	//set image nt header code, this is hex codes with hexlib//
	QWidget* IMAGE_NT_HEADER_s =		new QWidget;

	HexLib::HexLib *nt_header_hex = new HexLib::HexLib(this);
	nt_header_hex->setData(*hex_f);
	nt_header_hex->setData(nt_header_hex->data(mzh.getAddressOfPeHeader(), (int)0xF8));

	QHBoxLayout *nt_header_hbox = new QHBoxLayout(this);
	nt_header_hbox->addWidget(nt_header_hex);
	nt_header_hbox->setContentsMargins(0, 0, 0, 0);

	IMAGE_NT_HEADER_s->setLayout(nt_header_hbox);

	//set signature code//
	QTableWidget* SIGNATURE_s = new QTableWidget;

	SIGNATURE_s->setRowCount(1);
	SIGNATURE_s->setColumnCount(3);
	SIGNATURE_s->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
	SIGNATURE_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	SIGNATURE_s->verticalHeader()->setVisible(false);
	SIGNATURE_s->setShowGrid(false);
	SIGNATURE_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	SIGNATURE_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	SIGNATURE_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	SIGNATURE_s->setStyleSheet("font-size : 13px");

	switch (type) { // depends on the type of file.
		case PeLib::PEFILE32:
			setTableItem(SIGNATURE_s, 0, "NT Signature", toString(peh32.getNtSignature()));
			break;
		case PeLib::PEFILE64:
			setTableItem(SIGNATURE_s, 0, "NT Signature", toString(peh64.getNtSignature()));
			break;
	}
	
	//set image file header//
	QTableWidget* IMAGE_FILE_HEADER_s = new QTableWidget;

	IMAGE_FILE_HEADER_s->setRowCount(7);
	IMAGE_FILE_HEADER_s->setColumnCount(3);
	IMAGE_FILE_HEADER_s->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
	IMAGE_FILE_HEADER_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	IMAGE_FILE_HEADER_s->verticalHeader()->setVisible(false);
	IMAGE_FILE_HEADER_s->setShowGrid(false);
	IMAGE_FILE_HEADER_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	IMAGE_FILE_HEADER_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	IMAGE_FILE_HEADER_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	IMAGE_FILE_HEADER_s->setStyleSheet("font-size : 13px");

	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		setTableItem(IMAGE_FILE_HEADER_s, 0, "Machine", toString(peh32.getMachine()));
		setTableItem(IMAGE_FILE_HEADER_s, 1, "NumberOfSections", toString(peh32.getNumberOfSections()));
		setTableItem(IMAGE_FILE_HEADER_s, 2, "TimeDateStampe", toString(peh32.getTimeDateStamp()));
		setTableItem(IMAGE_FILE_HEADER_s, 3, "PointerToSymbolTable", toString(peh32.getPointerToSymbolTable()));
		setTableItem(IMAGE_FILE_HEADER_s, 4, "NumberOfSymbols", toString(peh32.getNumberOfSymbols()));
		setTableItem(IMAGE_FILE_HEADER_s, 5, "SizeOfOptionalHeader", toString(peh32.getSizeOfOptionalHeader()));
		setTableItem(IMAGE_FILE_HEADER_s, 6, "Characteristics", toString(peh32.getCharacteristics()));
		break;
	case PeLib::PEFILE64:
		setTableItem(IMAGE_FILE_HEADER_s, 0, "Machine", toString(peh64 .getMachine()));
		setTableItem(IMAGE_FILE_HEADER_s, 1, "NumberOfSections", toString(peh64.getNumberOfSections()));
		setTableItem(IMAGE_FILE_HEADER_s, 2, "TimeDateStampe", toString(peh64.getTimeDateStamp()));
		setTableItem(IMAGE_FILE_HEADER_s, 3, "PointerToSymbolTable", toString(peh64.getPointerToSymbolTable()));
		setTableItem(IMAGE_FILE_HEADER_s, 4, "NumberOfSymbols", toString(peh64.getNumberOfSymbols()));
		setTableItem(IMAGE_FILE_HEADER_s, 5, "SizeOfOptionalHeader", toString(peh64.getSizeOfOptionalHeader()));
		setTableItem(IMAGE_FILE_HEADER_s, 6, "Characteristics", toString(peh64.getCharacteristics()));;
		break;
	}


	//set image optional header//
	QTableWidget* IMAGE_OPTIONAL_HEADER_s = new QTableWidget;

	IMAGE_OPTIONAL_HEADER_s->setRowCount(29);
	IMAGE_OPTIONAL_HEADER_s->setColumnCount(3);
	IMAGE_OPTIONAL_HEADER_s->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
	IMAGE_OPTIONAL_HEADER_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	IMAGE_OPTIONAL_HEADER_s->verticalHeader()->setVisible(false);
	IMAGE_OPTIONAL_HEADER_s->setShowGrid(false);
	IMAGE_OPTIONAL_HEADER_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	IMAGE_OPTIONAL_HEADER_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	IMAGE_OPTIONAL_HEADER_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	IMAGE_OPTIONAL_HEADER_s->setStyleSheet("font-size : 13px");

	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 0, "Magic", toString(peh32.getMagic()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 1, "MajorLinkerVersion", toString(peh32.getMajorLinkerVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 2, "MinorLinkerVersion", toString(peh32.getMinorLinkerVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 3, "SizeOfCode", toString(peh32.getSizeOfCode()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 4, "SizeOfInitializedData", toString(peh32.getSizeOfInitializedData()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 5, "SizeOfUninitializedData", toString(peh32.getSizeOfUninitializedData()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 6, "AddressOfEntryPoint", toString(peh32.getAddressOfEntryPoint()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 7, "BaseOfCode", toString(peh32.getBaseOfCode()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 8, "ImageBase", toString(peh32.getImageBase()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 9, "SectionAlignment", toString(peh32.getSectionAlignment()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 10, "FileAlignment", toString(peh32.getFileAlignment()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 11, "MajorOperatingSystemVersion", toString(peh32.getMajorOperatingSystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 12, "MinorOperatingSystemVersion", toString(peh32.getMinorOperatingSystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 13, "MajorImageVersion", toString(peh32.getMajorImageVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 14, "MinorImageVersion", toString(peh32.getMinorImageVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 15, "MajorSubsystemVersion", toString(peh32.getMajorSubsystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 16, "MinorSubsystemVersion", toString(peh32.getMinorSubsystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 17, "Win32VersionValue", toString(peh32.getWin32VersionValue()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 18, "SizeOfImage", toString(peh32.getSizeOfImage()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 19, "SizeOfHeaders", toString(peh32.getSizeOfHeaders()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 20, "CheckSum", toString(peh32.getCheckSum()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 21, "Subsystem", toString(peh32.getSubsystem()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 22, "DllCharacteristics", toString(peh32.getDllCharacteristics()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 23, "SizeOfStackReserve", toString(peh32.getSizeOfStackReserve()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 24, "SizeOfStackCommit", toString(peh32.getSizeOfStackCommit()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 25, "SizeOfHeapReserve", toString(peh32.getSizeOfHeapReserve()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 26, "SizeOfHeapCommit", toString(peh32.getSizeOfHeapCommit()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 27, "LoaderFlags", toString(peh32.getLoaderFlags()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 28, "NumberOfRvaAndSizes", toString(peh32.getNumberOfRvaAndSizes()));
		break;
	case PeLib::PEFILE64:
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 0, "Magic", toString(peh64.getMagic()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 1, "MajorLinkerVersion", toString(peh64.getMajorLinkerVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 2, "MinorLinkerVersion", toString(peh64.getMinorLinkerVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 3, "SizeOfCode", toString(peh64.getSizeOfCode()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 4, "SizeOfInitializedData", toString(peh64.getSizeOfInitializedData()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 5, "SizeOfUninitializedData", toString(peh64.getSizeOfUninitializedData()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 6, "AddressOfEntryPoint", toString(peh64.getAddressOfEntryPoint()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 7, "BaseOfCode", toString(peh64.getBaseOfCode()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 8, "ImageBase", toString(peh64.getImageBase()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 9, "SectionAlignment", toString(peh64.getSectionAlignment()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 10, "FileAlignment", toString(peh64.getFileAlignment()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 11, "MajorOperatingSystemVersion", toString(peh64.getMajorOperatingSystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 12, "MinorOperatingSystemVersion", toString(peh64.getMinorOperatingSystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 13, "MajorImageVersion", toString(peh64.getMajorImageVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 14, "MinorImageVersion", toString(peh64.getMinorImageVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 15, "MajorSubsystemVersion", toString(peh64.getMajorSubsystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 16, "MinorSubsystemVersion", toString(peh64.getMinorSubsystemVersion()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 17, "Win32VersionValue", toString(peh64.getWin32VersionValue()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 18, "SizeOfImage", toString(peh64.getSizeOfImage()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 19, "SizeOfHeaders", toString(peh64.getSizeOfHeaders()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 20, "CheckSum", toString(peh64.getCheckSum()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 21, "Subsystem", toString(peh64.getSubsystem()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 22, "DllCharacteristics", toString(peh64.getDllCharacteristics()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 23, "SizeOfStackReserve", toString(peh64.getSizeOfStackReserve()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 24, "SizeOfStackCommit", toString(peh64.getSizeOfStackCommit()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 25, "SizeOfHeapReserve", toString(peh64.getSizeOfHeapReserve()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 26, "SizeOfHeapCommit", toString(peh64.getSizeOfHeapCommit()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 27, "LoaderFlags", toString(peh64.getLoaderFlags()));
		setTableItem(IMAGE_OPTIONAL_HEADER_s, 28, "NumberOfRvaAndSizes", toString(peh64.getNumberOfRvaAndSizes()));
		break;
	}

	//set image data directory//
	QTableWidget* IMAGE_DATA_DIRECTORY_s = new QTableWidget;

	type == PeLib::PEFILE32 ? IMAGE_DATA_DIRECTORY_s->setRowCount(peh32.getNumberOfRvaAndSizes() * 2) : IMAGE_DATA_DIRECTORY_s->setRowCount(peh64.getNumberOfRvaAndSizes() * 2);
	IMAGE_DATA_DIRECTORY_s->setColumnCount(4);
	IMAGE_DATA_DIRECTORY_s->setHorizontalHeaderLabels(QStringList() << "TableName" << "Description" << "Data" << "Value");
	IMAGE_DATA_DIRECTORY_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	IMAGE_DATA_DIRECTORY_s->verticalHeader()->setVisible(false);
	IMAGE_DATA_DIRECTORY_s->setShowGrid(false);
	IMAGE_DATA_DIRECTORY_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	IMAGE_DATA_DIRECTORY_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	IMAGE_DATA_DIRECTORY_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	IMAGE_DATA_DIRECTORY_s->setStyleSheet("font-size : 13px");

	
	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		for (int i = 0, j = 0 ; i < peh32.getNumberOfRvaAndSizes(); i++, j += 2) {
			setTableItem(IMAGE_DATA_DIRECTORY_s, j, tabnames[i], "(RVA)", toString(peh32.getImageDataDirectoryRva(i)));
			setTableItem(IMAGE_DATA_DIRECTORY_s, j + 1, tabnames[i], "(Size)", toString(peh32.getImageDataDirectorySize(i)));
		}
		break;
	case PeLib::PEFILE64:
		for (int i = 0, j = 0; i < peh32.getNumberOfRvaAndSizes(); i++, j += 2) {
			setTableItem(IMAGE_DATA_DIRECTORY_s, j, tabnames[i], "(RVA)", toString(peh64.getImageDataDirectoryRva(i)));
			setTableItem(IMAGE_DATA_DIRECTORY_s, j + 1, tabnames[i], "(Size)", toString(peh64.getImageDataDirectorySize(i)));
		}
		break;
	}

	//set section header, this hedear just stay //
	QWidget* SECTION_HEADER_s =			new QWidget;
	
	//set section body, this hedear just stay //
	QWidget* SECTION_BODY_s =			new QWidget;
	
	//set export directory//
	QTableWidget* EXPORT_DIRECTORY_s = new QTableWidget;

	EXPORT_DIRECTORY_s->setRowCount(12 + (exp.getNumberOfFunctions() * 4));
	EXPORT_DIRECTORY_s->setColumnCount(3);
	EXPORT_DIRECTORY_s->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
	EXPORT_DIRECTORY_s->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	EXPORT_DIRECTORY_s->verticalHeader()->setVisible(false);
	EXPORT_DIRECTORY_s->setShowGrid(false);
	EXPORT_DIRECTORY_s->setEditTriggers(QAbstractItemView::NoEditTriggers);
	EXPORT_DIRECTORY_s->setSelectionBehavior(QAbstractItemView::SelectRows);
	EXPORT_DIRECTORY_s->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	EXPORT_DIRECTORY_s->setStyleSheet("font-size : 13px");

	setTableItem(EXPORT_DIRECTORY_s, 0, "Base", toString(exp.getBase()));
	setTableItem(EXPORT_DIRECTORY_s, 1, "Characteristics", toString(exp.getCharacteristics()));
	setTableItem(EXPORT_DIRECTORY_s, 2, "TimeDateStamp", toString(exp.getTimeDateStamp()));
	setTableItem(EXPORT_DIRECTORY_s, 3, "MajorVersion", toString(exp.getMajorVersion()));
	setTableItem(EXPORT_DIRECTORY_s, 4, "MinorVersion", toString(exp.getMinorVersion()));
	setTableItem(EXPORT_DIRECTORY_s, 5, "Name", toString(exp.getName()));
	setTableItem(EXPORT_DIRECTORY_s, 6, "NumberOfFunctions", toString(exp.getNumberOfFunctions()));
	setTableItem(EXPORT_DIRECTORY_s, 7, "NumberOfNames", toString(exp.getNumberOfNames()));
	setTableItem(EXPORT_DIRECTORY_s, 8, "AddressOfFunctions", toString(exp.getAddressOfFunctions()));
	setTableItem(EXPORT_DIRECTORY_s, 9, "AddressOfNames", toString(exp.getAddressOfNames()));
	setTableItem(EXPORT_DIRECTORY_s, 10 ,"AddressOfNameOrdinals", toString(exp.getAddressOfNameOrdinals()));
	
	for (int i = 0, j = 0; i < exp.getNumberOfFunctions(); i++, j += 4) {
		setTableItem(EXPORT_DIRECTORY_s, 12 + j, "Name", exp.getFunctionName(i));
		setTableItem(EXPORT_DIRECTORY_s, 12 + j + 1, "Ordinal (w/o Base)", toString(exp.getFunctionOrdinal(i)));
		setTableItem(EXPORT_DIRECTORY_s, 12 + j + 2, "Address", toString(exp.getAddressOfFunction(i)));
	}


	//set import directory, this hedear just stay //
	QWidget* IMPORT_DIRECTORY_s =		new QWidget;

	//add widget to stackedwidget
	stackedWidget = new QStackedWidget;
	stackedWidget->addWidget(IMAGE_DOS_HEADER_s);
	stackedWidget->addWidget(DOS_STUB_PROGRAM_s);
	stackedWidget->addWidget(IMAGE_NT_HEADER_s);
	stackedWidget->addWidget(SIGNATURE_s);
	stackedWidget->addWidget(IMAGE_FILE_HEADER_s);
	stackedWidget->addWidget(IMAGE_OPTIONAL_HEADER_s);
	stackedWidget->addWidget(IMAGE_DATA_DIRECTORY_s);
	stackedWidget->addWidget(EXPORT_DIRECTORY_s);

	//section header elements//
	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		for (int i = 0, j = 0; i < peh32.getNumberOfRvaAndSizes(); i++, j += 2) {
			setTableItem(IMAGE_DATA_DIRECTORY_s, j, tabnames[i], "(RVA)", toString(peh32.getImageDataDirectoryRva(i)));
			setTableItem(IMAGE_DATA_DIRECTORY_s, j + 1, tabnames[i], "(Size)", toString(peh32.getImageDataDirectorySize(i)));
		}
		break;
	case PeLib::PEFILE64:
		for (int i = 0, j = 0; i < peh32.getNumberOfRvaAndSizes(); i++, j += 2) {
			setTableItem(IMAGE_DATA_DIRECTORY_s, j, tabnames[i], "(RVA)", toString(peh64.getImageDataDirectoryRva(i)));
			setTableItem(IMAGE_DATA_DIRECTORY_s, j + 1, tabnames[i], "(Size)", toString(peh64.getImageDataDirectorySize(i)));
		}
		break;
	}

	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		for (int i = 0; i < peh32.getNumberOfSections(); i++) {
			QTableWidget *ss = new QTableWidget();
			ss->setRowCount(10);
			ss->setColumnCount(3);
			ss->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
			ss->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
			ss->verticalHeader()->setVisible(false);
			ss->setShowGrid(false);
			ss->setEditTriggers(QAbstractItemView::NoEditTriggers);
			ss->setSelectionBehavior(QAbstractItemView::SelectRows);
			ss->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
			ss->setStyleSheet("font-size : 13px");

			setTableItem(ss, 0, "name", peh32.getSectionName(i));
			setTableItem(ss, 1, "VirtualSize", toString(peh32.getVirtualSize(i)));
			setTableItem(ss, 2, "VirtualAddress", toString(peh32.getVirtualAddress(i)));
			setTableItem(ss, 3, "SizeOfRawData", toString(peh32.getSizeOfRawData(i)));
			setTableItem(ss, 4, "PointerToRawData", toString(peh32.getPointerToRawData(i)));
			setTableItem(ss, 5, "PointerToRelocations", toString(peh32.getPointerToRelocations(i)));
			setTableItem(ss, 6, "PointerToLinenumbers", toString(peh32.getPointerToLinenumbers(i)));
			setTableItem(ss, 7, "NumberOfRelocations", toString(peh32.getNumberOfRelocations(i)));
			setTableItem(ss, 8, "NumberOfLineNumbers", toString(peh32.getNumberOfLinenumbers(i)));
			setTableItem(ss, 9, "Characteristics", toString(peh32.getCharacteristics(i)));
			stackedWidget->addWidget(ss);
		}
		break;
	case PeLib::PEFILE64:
		for (int i = 0; i < peh64.getNumberOfSections(); i++) {
			QTableWidget *ss = new QTableWidget();
			ss->setRowCount(10);
			ss->setColumnCount(3);
			ss->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
			ss->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
			ss->verticalHeader()->setVisible(false);
			ss->setShowGrid(false);
			ss->setEditTriggers(QAbstractItemView::NoEditTriggers);
			ss->setSelectionBehavior(QAbstractItemView::SelectRows);
			ss->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
			ss->setStyleSheet("font-size : 13px");

			setTableItem(ss, 0, "name", peh64.getSectionName(i));
			setTableItem(ss, 1, "VirtualSize", toString(peh64.getVirtualSize(i)));
			setTableItem(ss, 2, "VirtualAddress", toString(peh64.getVirtualAddress(i)));
			setTableItem(ss, 3, "SizeOfRawData", toString(peh64.getSizeOfRawData(i)));
			setTableItem(ss, 4, "PointerToRawData", toString(peh64.getPointerToRawData(i)));
			setTableItem(ss, 5, "PointerToRelocations", toString(peh64.getPointerToRelocations(i)));
			setTableItem(ss, 6, "PointerToLinenumbers", toString(peh64.getPointerToLinenumbers(i)));
			setTableItem(ss, 7, "NumberOfRelocations", toString(peh64.getNumberOfRelocations(i)));
			setTableItem(ss, 8, "NumberOfLineNumbers", toString(peh64.getNumberOfLinenumbers(i)));
			setTableItem(ss, 9, "Characteristics", toString(peh64.getCharacteristics(i)));
			stackedWidget->addWidget(ss);
		}
		break;
	}

	//section body elements with hex//
	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		for (int i = 0; i < peh32.getNumberOfSections(); i++) {
			QWidget* ss = new QWidget;
			HexLib::HexLib *hx = new HexLib::HexLib(this);
			hx->setData(*hex_f);
			hx->setData(hx->data(peh32.getPointerToRawData(i), peh32.getPointerToRawData(i) + peh32.getSizeOfRawData(i)));

			QHBoxLayout *hbox = new QHBoxLayout(this);
			hbox->addWidget(hx);
			hbox->setContentsMargins(0, 0, 0, 0);
			ss->setLayout(hbox);
			stackedWidget->addWidget(ss);
		}

		break;
	case PeLib::PEFILE64:
		for (int i = 0; i < peh64.getNumberOfSections(); i++) {
			QWidget* ss = new QWidget;
			HexLib::HexLib *hx = new HexLib::HexLib(this);
			hx->setData(*hex_f);
			hx->setData(hx->data(peh64.getPointerToRawData(i), peh64.getPointerToRawData(i) + peh64.getSizeOfRawData(i)));

			QHBoxLayout *hbox = new QHBoxLayout(this);
			hbox->addWidget(hx);
			hbox->setContentsMargins(0, 0, 0, 0);
			ss->setLayout(hbox);
			stackedWidget->addWidget(ss);
		}
		break;
	}

	//import directory elements//
	switch (type) { // depends on the type of file.
	case PeLib::PEFILE32:
		for (int i = 0; i < imp32.getNumberOfFiles(PeLib::OLDDIR); i++) {
			QTableWidget *ss = new QTableWidget();
			ss->setRowCount(7 + 5 * imp32.getNumberOfFunctions(i, PeLib::OLDDIR));
			ss->setColumnCount(3);
			ss->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
			ss->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
			ss->verticalHeader()->setVisible(false);
			ss->setShowGrid(false);
			ss->setEditTriggers(QAbstractItemView::NoEditTriggers);
			ss->setSelectionBehavior(QAbstractItemView::SelectRows);
			ss->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
			ss->setStyleSheet("font-size : 13px");

			setTableItem(ss, 0, "DLL Name", imp32.getFileName(i, PeLib::OLDDIR));
			setTableItem(ss, 1, "OriginalFirstThunk", toString(imp32.getOriginalFirstThunk(i, PeLib::OLDDIR)));
			setTableItem(ss, 2, "TimeDateStamp", toString(imp32.getTimeDateStamp(i, PeLib::OLDDIR)));
			setTableItem(ss, 3, "ForwarderChain", toString(imp32.getForwarderChain(i, PeLib::OLDDIR)));
			setTableItem(ss, 4, "Name", toString(imp32.getRvaOfName(i, PeLib::OLDDIR)));
			setTableItem(ss, 5, "FirstThunk", toString(imp32.getFirstThunk(i, PeLib::OLDDIR)));

			for (unsigned int j = 0, k = 0; j<imp32.getNumberOfFunctions(i, PeLib::OLDDIR); j++, k += 5)
			{
				setTableItem(ss, 7 + k, "Function Name", imp32.getFunctionName(i, j, PeLib::OLDDIR));
				setTableItem(ss, 7 + k + 1, "Hint", toString(imp32.getFunctionHint(i, j, PeLib::OLDDIR)));
				setTableItem(ss, 7 + k + 2, "First Thunk", toString(imp32.getFirstThunk(i, j, PeLib::OLDDIR)));
				setTableItem(ss, 7 + k + 3, "Original First Thunk", toString(imp32.getOriginalFirstThunk(i, j, PeLib::OLDDIR)));
			}
			stackedWidget->addWidget(ss);
		}
		break;

	case PeLib::PEFILE64:
		for (int i = 0; i < imp64.getNumberOfFiles(PeLib::OLDDIR); i++) {
			QTableWidget *ss = new QTableWidget();
			ss->setRowCount(7 + 5 * imp64.getNumberOfFunctions(i, PeLib::OLDDIR));
			ss->setColumnCount(3);
			ss->setHorizontalHeaderLabels(QStringList() << "Description" << "Data" << "Value");
			ss->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
			ss->verticalHeader()->setVisible(false);
			ss->setShowGrid(false);
			ss->setEditTriggers(QAbstractItemView::NoEditTriggers);
			ss->setSelectionBehavior(QAbstractItemView::SelectRows);
			ss->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
			ss->setStyleSheet("font-size : 13px");

			setTableItem(ss, 0, "DLL Name", imp64.getFileName(i, PeLib::OLDDIR));
			setTableItem(ss, 1, "OriginalFirstThunk", toString(imp64.getOriginalFirstThunk(i, PeLib::OLDDIR)));
			setTableItem(ss, 2, "TimeDateStamp", toString(imp64.getTimeDateStamp(i, PeLib::OLDDIR)));
			setTableItem(ss, 3, "ForwarderChain", toString(imp64.getForwarderChain(i, PeLib::OLDDIR)));
			setTableItem(ss, 4, "Name", toString(imp64.getRvaOfName(i, PeLib::OLDDIR)));
			setTableItem(ss, 5, "FirstThunk", toString(imp64.getFirstThunk(i, PeLib::OLDDIR)));

			for (unsigned int j = 0, k = 0; j<imp64.getNumberOfFunctions(i, PeLib::OLDDIR); j++, k += 5)
			{
				setTableItem(ss, 7 + k, "Function Name", imp64.getFunctionName(i, j, PeLib::OLDDIR));
				setTableItem(ss, 7 + k + 1, "Hint", toString(imp64.getFunctionHint(i, j, PeLib::OLDDIR)));
				setTableItem(ss, 7 + k + 2, "First Thunk", toString(imp64.getFirstThunk(i, j, PeLib::OLDDIR)));
				setTableItem(ss, 7 + k + 3, "Original First Thunk", toString(imp64.getOriginalFirstThunk(i, j, PeLib::OLDDIR)));
			}
			stackedWidget->addWidget(ss);
		}
		break;
	}

	// --------------------- layout info ----------------------- //
	QSplitter *splitterWidget = new QSplitter(Qt::Horizontal, this);
	splitterWidget->addWidget(treeView);
	splitterWidget->addWidget(stackedWidget);

	QList<int> lst = splitterWidget->sizes();	// split position
	lst.replace(0, this->width() / 0.7);
	lst.replace(1, this->width() / 0.3);
	splitterWidget->setSizes(lst);

	QHBoxLayout *hboxWidget = new QHBoxLayout(this);
	hboxWidget->addWidget(splitterWidget);
	hboxWidget->setContentsMargins(0, 0, 0, 0);
	setLayout(hboxWidget);

	// --------------------- css & optional info ----------------------- //
	stackedWidget->setStyleSheet("background-color : rgb(53,53,53)");
	
	treeView->setStyleSheet("background-color : rgb(48, 48, 48); color : white; font-size : 13px");
	treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	treeView->setHeaderHidden(true);
	
	splitterWidget->setStyleSheet("QSplitter::handle{background : rgb(60, 60, 60)};");
	
	FILE->setFont(QFont::QFont("", -1, QFont::Bold));
	FILE->setFlags(Qt::ItemIsEnabled);
	SECTION_HEADER->setFont(QFont::QFont("", -1, QFont::Bold));
	SECTION_HEADER->setFlags(Qt::ItemIsEnabled);
	SECTION_BODY->setFont(QFont::QFont("", -1, QFont::Bold));
	SECTION_BODY->setFlags(Qt::ItemIsEnabled);
	IMPORT_DIRECTORY->setFont(QFont::QFont("", -1, QFont::Bold));
	IMPORT_DIRECTORY->setFlags(Qt::ItemIsEnabled);

	// --------------------- post process ----------------------- //
	QItemSelectionModel *selectionModel = treeView->selectionModel();
	connect(selectionModel, SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
		this, SLOT(selectionChangedSlot(const QItemSelection &, const QItemSelection &)));

	delete pef;
	pef = nullptr;

	hex_f->close();
}

void PeView::selectionChangedSlot(const QItemSelection & /*newSelection*/, const QItemSelection & /*oldSelection*/)
{
	//get the text of the selected item
	const QModelIndex index = treeView->selectionModel()->currentIndex();
	QString selectedText = index.data(Qt::DisplayRole).toString();
	
	//find out stackWidget
	if (selectedText.toStdString() == "IMAGE_DOS_HEDEAR")
		stackedWidget->setCurrentIndex(0);
	else if (selectedText.toStdString() == "DOS_STUB_PROGRAM")
		stackedWidget->setCurrentIndex(1);
	else if (selectedText.toStdString() == "IMAGE_NT_HEADER")
		stackedWidget->setCurrentIndex(2);
	else if (selectedText.toStdString() == "Signature")
		stackedWidget->setCurrentIndex(3);
	else if (selectedText.toStdString() == "IMAGE_FILE_HEADER")
		stackedWidget->setCurrentIndex(4);
	else if (selectedText.toStdString() == "IMAGE_OPTIONAL_HEADER")
		stackedWidget->setCurrentIndex(5);
	else if (selectedText.toStdString() == "IMAGE_DATA_DIRECTORY")
		stackedWidget->setCurrentIndex(6);
	else if (selectedText.toStdString() == "EXPORT_DIRECTORY")
		stackedWidget->setCurrentIndex(7);

	QModelIndex seekRoot = index;
	//section header stack	
	if (seekRoot.parent().data(Qt::DisplayRole).toString() == "Section Header")
	{
		stackedWidget->setCurrentIndex(index.row()+ 8); 
	}
	
	//section body stack
	if (seekRoot.parent().data(Qt::DisplayRole).toString() == "Section Body")
	{
		stackedWidget->setCurrentIndex(index.row() + 8 + numberOfSection);
	}

	//section body stack
	if (seekRoot.parent().data(Qt::DisplayRole).toString() == "IMPORT_DIRECTORY")
	{
		stackedWidget->setCurrentIndex(index.row() + 8 + numberOfSection * 2);
	}
}
