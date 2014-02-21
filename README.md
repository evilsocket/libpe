# libpe

A C/C++ library to parse Windows portable executables ( both PE32 and PE32+ ) written with **speed** and **stability** in mind.

Copyleft of Simone Margaritelli <evilsocket@gmail.com>  
[http://www.evilsocket.net/](http://www.evilsocket.net/)

#### Example  

PE32/PE32+ sections, imports and exports dumper.

    #include <libpe.h>

	int main( int argc, char **argv )
	{
		PE pe = {0}; 
		DWORD status;
		unsigned char hash[16] = {0};
		char szHash[33] = {0};

		if( argc < 2 )
		{
			printf( "Usage: %s <pe-filename>\n", argv[0] );
			exit(1);
		}

		status = peOpenFile( &pe, argv[1] );
		if( status != ERROR_SUCCESS )
		{
			printf( "Open error: %08X\n", status );
			goto done;
		}

		printf( "TYPE        : %s\n", pe.Headers.Plus ? "PE32+" : "PE32" );
		printf( "IMAGE BASE  : %08llX\n", pe.qwBaseAddress );
		printf( "ENTRY POINT : %08llX ( %08llX )\n", pe.EntryPoint.VA, pe.EntryPoint.Offset );

		printf( "\n" );
		
		printf( "SECTIONS ( %d ):\n", pe.Sections.dwNumber );

		// print each section name, start address, end address raw size and virtual size
		PE_FOREACH_SECTION( &pe, pSection )
		{
			printf
			( 
				"  %-15s %08llX - %08llX ( rsize=%d, vsize=%d )\n",
				pSection->Name, 
				pe.qwBaseAddress + pSection->VirtualAddress, 
				pe.qwBaseAddress + pSection->VirtualAddress + pSection->SizeOfRawData, 
				pSection->SizeOfRawData, 
				pSection->Misc.VirtualSize 
			);
		}

		printf( "\n" );

		// parse the export table with a maximum of 100 exported symbols
		status = peParseExportTable( &pe, 100 );
		if( status != ERROR_SUCCESS )
		{
			printf( "Export parse error: %d\n", status );
			goto done;
		}

		// print any entry in the export table
		if( PE_HAS_TABLE( &pe, ExportTable ) )
		{
			printf( "EXPORT TABLE ( %d ) [%08llX]:\n", pe.ExportTable.Symbols.elements, pe.ExportTable.Address.VA );

			PE_FOREACH_EXPORTED_SYMBOL( &pe, pSymbol )
			{
				printf( "(%05u) [%08llX] %s\n", pSymbol->Ordinal, pSymbol->Address.VA, pSymbol->Name );
			}
		
			printf( "\n" );
		}

		// print any entry in the import table ( resolve imports by ordinals into imports by name when possible )
		status = peParseImportTable( &pe, PE_IMPORT_OPT_RESOLVE_ORDINALS );
		if( status == ERROR_SUCCESS && PE_HAS_TABLE( &pe, ImportTable ) )
		{
			printf( "IMPORT TABLE ( %d ) [%08llX]:\n", pe.ImportTable.Modules.elements, pe.ImportTable.Address.VA );

			PE_FOREACH_IMPORTED_MODULE( &pe, pModule )
			{
				printf( "  %s ( %d )\n", pModule->Name, pModule->Symbols.elements );

				PE_FOREACH_MODULE_SYMBOL( pModule, pSymbol )
				{
					if( PE_SYMBOL_HAS_NAME( pSymbol ) )
					{
						printf( "    [%08llX] %s\n", pSymbol->Address.VA, pSymbol->Name );
					}
					else
					{
						printf( "    [%08llX] ORD %d\n", pSymbol->Address.VA, pSymbol->Ordinal );
					}
				}
			}
		}

	done:

		peClose(&pe);

		return 0;
	}
    
#### License  

Release under the GPL 3 license.