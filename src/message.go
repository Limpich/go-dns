package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

type DnsMessage struct {
	Header     DnsMessageHeader
	Questions  []DnsMessageQuestionSectionEntry
	Answers    []DnsMessageResourceEntry
	Authority  []DnsMessageResourceEntry
	Additional []DnsMessageResourceEntry
}

const DnsMessageOpCodeStandard uint8 = 0
const DnsMessageOpCodeInverse uint8 = 1
const DnsMessageOpCodeStatus uint8 = 2

const DnsMessageResponseCodeOk uint8 = 0
const DnsMessageResponseCodeFormatError uint8 = 1
const DnsMessageResponseCodeServerFailure uint8 = 2

type DnsMessageHeader struct {
	TransactionID uint16

	isResponse          bool  // 1 bit
	OpCode              uint8 // 4 bit
	AuthoritativeAnswer bool  // 1 bit
	TrunCation          bool  // 1 bit
	RecursionDesired    bool  // 1 bit
	RecursionAvailable  bool  // 1 bit
	_Reserved           uint8 // 3 bit
	ResponseCode        uint8 // 4 bit

	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

const QType_A uint16 = 1
const QType_TXT uint16 = 16
const QClass_IN uint16 = 1

type DnsMessageQuestionSectionEntry struct {
	QName  string
	QType  uint16
	QClass uint16
}

type DnsMessageResourceEntry struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RdLength uint16
	RdData   []byte
}

func ParseMessageFromBuffer(buf []byte, length int) (DnsMessage, error) {
	var err error

	result := DnsMessage{}
	result.Questions = make([]DnsMessageQuestionSectionEntry, 0)

	if length < 12 {
		return result, errors.New(MessageTooShort)
	}

	result.Header.TransactionID = binary.BigEndian.Uint16(buf[0:2])
	flags := binary.BigEndian.Uint16(buf[2:4])
	result.Header.QDCOUNT = binary.BigEndian.Uint16(buf[4:6])
	result.Header.ANCOUNT = binary.BigEndian.Uint16(buf[6:8])
	result.Header.NSCOUNT = binary.BigEndian.Uint16(buf[8:10])
	result.Header.ARCOUNT = binary.BigEndian.Uint16(buf[10:12])

	result.Header.isResponse = (uint8(flags>>15) & 0x01) == 1
	result.Header.OpCode = uint8(flags>>11) & 0x0F
	result.Header.AuthoritativeAnswer = (uint8(flags>>10) & 0x01) == 1
	result.Header.TrunCation = (uint8(flags>>9) & 0x01) == 1
	result.Header.RecursionDesired = (uint8(flags>>8) & 0x01) == 1
	result.Header.RecursionAvailable = (uint8(flags>>7) & 0x01) == 1
	result.Header._Reserved = uint8(flags>>4) & 0x07
	result.Header.ResponseCode = uint8(flags) & 0x0F

	var currentBufferOffset int = 12
	for i := 0; i < int(result.Header.QDCOUNT); i++ {
		questionEntry := DnsMessageQuestionSectionEntry{}

		questionEntry.QName, currentBufferOffset, err = readString(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		questionEntry.QType, currentBufferOffset, err = readUint16(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		questionEntry.QClass, currentBufferOffset, err = readUint16(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		result.Questions = append(result.Questions, questionEntry)
	}

	/**
	 * По-хорошему надо и остальные записи обработать, но они вроде как не должны приходить и мне лень
	 */

	for i := 0; i < int(result.Header.ARCOUNT); i++ {
		resourceEntry := DnsMessageResourceEntry{}

		resourceEntry.Name, currentBufferOffset, err = readString(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		resourceEntry.Type, currentBufferOffset, err = readUint16(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		resourceEntry.Class, currentBufferOffset, err = readUint16(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		resourceEntry.TTL, currentBufferOffset, err = readUint32(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		resourceEntry.RdLength, currentBufferOffset, err = readUint16(buf, length, currentBufferOffset)
		if err != nil {
			return result, err
		}

		if currentBufferOffset+int(resourceEntry.RdLength) > length {
			return result, errors.New(MessageParsingFailed)
		}

		resourceEntry.RdData = buf[currentBufferOffset : currentBufferOffset+int(resourceEntry.RdLength)]
		currentBufferOffset += int(resourceEntry.RdLength)

		result.Additional = append(result.Additional, resourceEntry)
	}

	return result, nil
}

func readUint16(buf []byte, length int, bufferOffset int) (uint16, int, error) {
	if bufferOffset+2 > length {
		return 0, bufferOffset, errors.New(MessageParsingFailed)
	}

	var result = binary.BigEndian.Uint16(buf[bufferOffset : bufferOffset+2])

	return result, bufferOffset + 2, nil
}

func readUint32(buf []byte, length int, bufferOffset int) (uint32, int, error) {
	if bufferOffset+4 > length {
		return 0, bufferOffset, errors.New(MessageParsingFailed)
	}

	var result = binary.BigEndian.Uint32(buf[bufferOffset : bufferOffset+4])

	return result, bufferOffset + 4, nil
}

func readString(buf []byte, length int, bufferOffset int) (string, int, error) {
	var parts []string = make([]string, 0)

	for {
		if bufferOffset > length {
			return "", bufferOffset, errors.New(MessageParsingFailed)
		}

		var nameLength = buf[bufferOffset]

		/** Сжатый формат */
		if nameLength == 0xC0 {
			var temp uint16 = binary.BigEndian.Uint16(buf[bufferOffset : bufferOffset+2])
			bufferOffset += 2

			var bufferOffsetPtr = int(((temp << 2) >> 2))
			part, _, err := readString(buf, length, bufferOffsetPtr)
			if err != nil {
				return "", bufferOffset, err
			}

			parts = append(parts, part)
		} else {
			bufferOffset++

			if nameLength != 0 {
				if bufferOffset+int(nameLength) > length {
					return "", bufferOffset, errors.New(MessageParsingFailed)
				}

				var part = string(buf[bufferOffset : bufferOffset+int(nameLength)])
				bufferOffset += int(nameLength)

				parts = append(parts, part)
			} else {
				break
			}
		}
	}

	return strings.Join(parts, "."), bufferOffset, nil
}

func WriteMessageToBuffer(message DnsMessage) ([]byte, int, error) {
	buf := make([]byte, 0)

	buf = binary.BigEndian.AppendUint16(buf, message.Header.TransactionID)

	var flags uint16 = 0

	if message.Header.isResponse {
		flags |= (1 << 15)
	}

	flags |= uint16(message.Header.OpCode) << 11

	if message.Header.AuthoritativeAnswer {
		flags |= (1 << 10)
	}

	if message.Header.TrunCation {
		flags |= (1 << 9)
	}

	if message.Header.RecursionDesired {
		flags |= (1 << 8)
	}

	if message.Header.RecursionAvailable {
		flags |= (1 << 7)
	}

	flags |= uint16(message.Header._Reserved) << 4
	flags |= uint16(message.Header.ResponseCode)

	buf = binary.BigEndian.AppendUint16(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, message.Header.QDCOUNT)
	buf = binary.BigEndian.AppendUint16(buf, message.Header.ANCOUNT)
	buf = binary.BigEndian.AppendUint16(buf, message.Header.NSCOUNT)
	buf = binary.BigEndian.AppendUint16(buf, message.Header.ARCOUNT)

	for i := 0; i < int(message.Header.QDCOUNT); i++ {
		buf = writeStringToBuffer(buf, message.Questions[i].QName)
		buf = binary.BigEndian.AppendUint16(buf, message.Questions[i].QType)
		buf = binary.BigEndian.AppendUint16(buf, message.Questions[i].QClass)
	}

	for i := 0; i < int(message.Header.ANCOUNT); i++ {
		buf = writeStringToBuffer(buf, message.Answers[i].Name)
		buf = binary.BigEndian.AppendUint16(buf, message.Answers[i].Type)
		buf = binary.BigEndian.AppendUint16(buf, message.Answers[i].Class)
		buf = binary.BigEndian.AppendUint32(buf, message.Answers[i].TTL)
		buf = binary.BigEndian.AppendUint16(buf, message.Answers[i].RdLength)
		buf = append(buf, message.Answers[i].RdData...)
	}

	return buf, len(buf), nil
}

func writeStringToBuffer(buf []byte, str string) []byte {
	var parts = strings.Split(str, ".")
	for i := 0; i < len(parts); i++ {
		buf = append(buf, byte(len(parts[i])))
		buf = append(buf, []byte(parts[i])...)
	}

	buf = append(buf, 0)

	return buf
}
