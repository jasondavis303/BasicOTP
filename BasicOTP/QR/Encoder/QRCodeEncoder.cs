/////////////////////////////////////////////////////////////////////
//
//	QR Code Encoder Library
//
//	QR Code encoder.
//
//	Author: Uzi Granot
//	Original Version: 1.0
//	Date: June 30, 2018
//	Copyright (C) 2018-2019 Uzi Granot. All Rights Reserved
//	For full version history please look at QREncoder.cs
//
//	QR Code Library C# class library and the attached test/demo
//  applications are free software.
//	Software developed by this author is licensed under CPOL 1.02.
//	Some portions of the QRCodeVideoDecoder are licensed under GNU Lesser
//	General Public License v3.0.
//
//	The solution is made of 3 projects:
//	1. QRCodeEncoderLibrary: QR code encoding.
//	2. QRCodeEncoderDemo: Create QR Code images.
//	3. QRCodeConsoleDemo: Demo app for net standard
//
//	The main points of CPOL 1.02 subject to the terms of the License are:
//
//	Source Code and Executable Files can be used in commercial applications;
//	Source Code and Executable Files can be redistributed; and
//	Source Code can be modified to create derivative works.
//	No claim of suitability, guarantee, or any warranty whatsoever is
//	provided. The software is provided "as-is".
//	The Article accompanying the Work may not be distributed or republished
//	without the Author's consent
//
/////////////////////////////////////////////////////////////////////
//
//	Version History:
//
//	Version 1.0 2018/06/30
//		Original revision
//
//	Version 1.1 2018/07/20
//		Consolidate DirectShowLib into one module removing unused code
//
//	Version 2.0 2019/05/15
//		Split the combined QRCode encoder and decoder to two solutions.
//		Add support for .net standard.
//		Add save image to png file without Bitmap class.
//	Version 2.1 2019/07/22
//		Add support for ECI Assignment Value
/////////////////////////////////////////////////////////////////////

using System;
using System.IO;

namespace QRCodeEncoderLibrary
	{
	class QRCodeEncoder : QREncoder
		{
		private static readonly byte[] PngFileSignature = new byte[] {137, (byte) 'P', (byte) 'N', (byte) 'G', (byte) '\r', (byte) '\n', 26, (byte) '\n'};

		private static readonly byte[] PngIendChunk = new byte[] {0, 0, 0, 0, (byte) 'I', (byte) 'E', (byte) 'N', (byte) 'D', 0xae, 0x42, 0x60, 0x82};

		/// <summary>
		/// Save QRCode image to PNG file
		/// </summary>
		/// <param name="FileName">PNG file name</param>
		public void SaveQRCodeToPngFile
				(
				string FileName
				)
			{
			// exceptions
			if(FileName == null)
				throw new ArgumentNullException("SaveQRCodeToPngFile: FileName is null");
			if(!FileName.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("SaveQRCodeToPngFile: FileName extension must be .png");
			if(QRCodeMatrix == null)
				throw new ApplicationException("QRCode must be encoded first");

            // file name to stream
            using Stream OutputStream = new FileStream(FileName, FileMode.Create, FileAccess.Write, FileShare.None);

            // save file
            SaveQRCodeToPngFile(OutputStream);
            return;
			}

		/// <summary>
		/// Save QRCode image to PNG stream
		/// </summary>
		/// <param name="OutputStream">PNG output stream</param>
		public void SaveQRCodeToPngFile
				(
				Stream OutputStream
				)
			{
			if(QRCodeMatrix == null)
				throw new ApplicationException("QRCode must be encoded first");

			// header
			byte[] Header = BuildPngHeader();

			// barcode data
			byte[] InputBuf = QRCodeMatrixToPng();

			// compress barcode data
			byte[] OutputBuf = PngImageData(InputBuf);

			// stream to binary writer
			BinaryWriter BW = new BinaryWriter(OutputStream);

			// write signature
			BW.Write(PngFileSignature, 0, PngFileSignature.Length);

			// write header
			BW.Write(Header, 0, Header.Length);

			// write image data
			BW.Write(OutputBuf, 0, OutputBuf.Length);

			// write end of file
			BW.Write(PngIendChunk, 0, PngIendChunk.Length);

			// flush all buffers
			BW.Flush();
			return;
			}

		internal byte[] BuildPngHeader()
			{ 
			// header
			byte[] Header = new byte[25];
					
			// header length
			Header[0] = 0;
			Header[1] = 0;
			Header[2] = 0;
			Header[3] = 13;

			// header label
			Header[4] = (byte) 'I';
			Header[5] = (byte) 'H';
			Header[6] = (byte) 'D';
			Header[7] = (byte) 'R';

			// image width
			int ImageDimension = QRCodeImageDimension;
			Header[8] = (byte) (ImageDimension >> 24);
			Header[9] = (byte) (ImageDimension >> 16);
			Header[10] = (byte) (ImageDimension >> 8);
			Header[11] = (byte) ImageDimension;

			// image height
			Header[12] = (byte) (ImageDimension >> 24);
			Header[13] = (byte) (ImageDimension >> 16);
			Header[14] = (byte) (ImageDimension >> 8);
			Header[15] = (byte) ImageDimension;

			// bit depth (1)
			Header[16] = 1;

			// color type (grey)
			Header[17] = 0;

			// Compression (deflate)
			Header[18] = 0;

			// filtering (up)
			Header[19] = 0; // 2;

			// interlace (none)
			Header[20] = 0;

			// crc
			uint Crc = CRC32.Checksum(Header, 4, 17);
			Header[21] = (byte) (Crc >> 24);
			Header[22] = (byte) (Crc >> 16);
			Header[23] = (byte) (Crc >> 8);
			Header[24] = (byte) Crc;

			// return header
			return Header;
			}

		internal static byte[] PngImageData
				(
				byte[] InputBuf
				)
			{
			// output buffer is:
			// Png IDAT length 4 bytes
			// Png chunk type IDAT 4 bytes
			// Png chunk data made of:
			//		header 2 bytes
			//		compressed data DataLen bytes
			//		adler32 input buffer checksum 4 bytes
			// Png CRC 4 bytes
			// Total output buffer length is 18 + DataLen

			// compress image
			byte[] OutputBuf = ZLibCompression.Compress(InputBuf);

			// png chunk data length
			int PngDataLen = OutputBuf.Length - 12;
			OutputBuf[0] = (byte) (PngDataLen >> 24);
			OutputBuf[1] = (byte) (PngDataLen >> 16);
			OutputBuf[2] = (byte) (PngDataLen >> 8);
			OutputBuf[3] = (byte) PngDataLen;

			// add IDAT
			OutputBuf[4] = (byte) 'I';
			OutputBuf[5] = (byte) 'D';
			OutputBuf[6] = (byte) 'A';
			OutputBuf[7] = (byte) 'T';

			// adler32 checksum
			uint ReadAdler32 = Adler32.Checksum(InputBuf, 0, InputBuf.Length);

			// ZLib checksum is Adler32 write it big endian order, high byte first
			int AdlerPtr = OutputBuf.Length - 8;
			OutputBuf[AdlerPtr++] = (byte) (ReadAdler32 >> 24);
			OutputBuf[AdlerPtr++] = (byte) (ReadAdler32 >> 16);
			OutputBuf[AdlerPtr++] = (byte) (ReadAdler32 >> 8);
			OutputBuf[AdlerPtr] = (byte) ReadAdler32;

			// crc
			uint Crc = CRC32.Checksum(OutputBuf, 4, OutputBuf.Length - 8);
			int CrcPtr = OutputBuf.Length - 4;
			OutputBuf[CrcPtr++] = (byte) (Crc >> 24);
			OutputBuf[CrcPtr++] = (byte) (Crc >> 16);
			OutputBuf[CrcPtr++] = (byte) (Crc >> 8);
			OutputBuf[CrcPtr++] = (byte) Crc;

			// successful exit
			return OutputBuf;
			}

		// convert barcode matrix to PNG image format
		internal byte[] QRCodeMatrixToPng()
			{
			// image width and height
			int ImageDimension = this.QRCodeImageDimension;

			// width in bytes including filter leading byte
			int PngWidth = (ImageDimension + 7) / 8 + 1;

			// PNG image array
			// array is all zeros in other words it is black image
			int PngLength = PngWidth * ImageDimension;
			byte[] PngImage = new byte[PngLength];

			// first row is a quiet zone and it is all white (filter is 0 none)
			int PngPtr;
			for(PngPtr = 1; PngPtr < PngWidth; PngPtr++) PngImage[PngPtr] = 255;

			// additional quiet zone rows are the same as first line (filter is 2 up)
			int PngEnd = QuietZone * PngWidth;
			for(; PngPtr < PngEnd; PngPtr += PngWidth) PngImage[PngPtr] = 2;

			// convert result matrix to output matrix
			for(int MatrixRow = 0; MatrixRow < QRCodeDimension; MatrixRow++)
				{
				// make next row all white (filter is 0 none)
				PngEnd = PngPtr + PngWidth;
				for(int PngCol = PngPtr + 1; PngCol < PngEnd; PngCol++) PngImage[PngCol] = 255;

				// add black to next row
				for(int MatrixCol = 0; MatrixCol < QRCodeDimension; MatrixCol++)
					{
					// bar is white
					if(!QRCodeMatrix[MatrixRow, MatrixCol]) continue;

					int PixelCol = ModuleSize * MatrixCol + QuietZone;
					int PixelEnd = PixelCol + ModuleSize;
					for(; PixelCol < PixelEnd; PixelCol++)
						{ 
						PngImage[PngPtr + (1 + PixelCol / 8)] &= (byte) ~(1 << (7 - (PixelCol & 7)));
						}
					}

				// additional rows are the same as the one above (filter is 2 up)
				PngEnd = PngPtr + ModuleSize * PngWidth;
				for(PngPtr += PngWidth; PngPtr < PngEnd; PngPtr += PngWidth) PngImage[PngPtr] = 2;
				}

			// bottom quiet zone and it is all white (filter is 0 none)
			PngEnd = PngPtr + PngWidth;
			for(PngPtr++; PngPtr < PngEnd; PngPtr++) PngImage[PngPtr] = 255;

			// additional quiet zone rows are the same as first line (filter is 2 up)
			for(; PngPtr < PngLength; PngPtr += PngWidth) PngImage[PngPtr] = 2;

			return PngImage;
			}
		}
	}
