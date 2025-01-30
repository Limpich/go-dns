package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type IDnsEngine interface {
	HandleMessage(buf []byte, length int) ([]byte, int, error)
}

type DnsEngine struct {
}

func (engine DnsEngine) HandleMessage(buf []byte, length int) ([]byte, int, error) {
	var err error

	fmt.Println("Parsing message...")
	message, err := ParseMessageFromBuffer(buf, length)

	var responseMessage = DnsMessage{
		Header: DnsMessageHeader{
			TransactionID:       message.Header.TransactionID,
			isResponse:          true,
			OpCode:              DnsMessageOpCodeStandard,
			AuthoritativeAnswer: false,
			TrunCation:          false,
			RecursionDesired:    false,
			RecursionAvailable:  false,
			ResponseCode:        DnsMessageResponseCodeOk,
			_Reserved:           0,
			QDCOUNT:             1,
			ANCOUNT:             0,
			NSCOUNT:             0,
			ARCOUNT:             0,
		},
		Questions:  message.Questions,
		Answers:    make([]DnsMessageResourceEntry, 0),
		Authority:  make([]DnsMessageResourceEntry, 0),
		Additional: make([]DnsMessageResourceEntry, 0),
	}

	if err != nil {
		responseMessage.Header.ResponseCode = DnsMessageResponseCodeFormatError
		fmt.Println("Parsing message error.")
		return WriteMessageToBuffer(responseMessage)
	}

	fmt.Println("Validating message...")

	err = validateMessage(message)
	if err != nil {
		responseMessage.Header.ResponseCode = DnsMessageResponseCodeFormatError
		fmt.Println("Validate message error.")
		return WriteMessageToBuffer(responseMessage)
	}

	fmt.Println("Preparing answer...")

	resourceEntry, ok, err := prepareResourceEntryForEntry(message.Questions[0])
	if !ok || err != nil {
		fmt.Println("Prepare answer error.")

		responseMessage.Header.ResponseCode = DnsMessageResponseCodeServerFailure
		return WriteMessageToBuffer(responseMessage)
	}

	responseMessage.Answers = append(responseMessage.Answers, resourceEntry)
	responseMessage.Header.ANCOUNT = 1

	return WriteMessageToBuffer(responseMessage)
}

func validateMessage(message DnsMessage) error {
	/** Сообщение не является запросом */
	if message.Header.isResponse {
		return errors.New(NotValidMessage)
	}

	switch message.Header.OpCode {
	case DnsMessageOpCodeStandard:
		/** Пустая QuestionSection или заявленный размер не совпадает с реальностью */
		if message.Header.QDCOUNT == 0 || int(message.Header.QDCOUNT) != len(message.Questions) {
			return errors.New(NotValidMessage)
		}

		if message.Header.QDCOUNT != 1 {
			return errors.New(ValidButNotImplemented)
		}

		for i := 0; i < int(message.Header.QDCOUNT); i++ {
			if message.Questions[0].QClass != QClass_IN {
				return errors.New(ValidButNotImplemented)
			}

			if message.Questions[0].QType != QType_A && message.Questions[0].QType != QType_TXT {
				return errors.New(ValidButNotImplemented)
			}
		}
	case DnsMessageOpCodeInverse:
	case DnsMessageOpCodeStatus:
		return errors.New(ValidButNotImplemented)

	default:
		/** Некорректный OpCode */
		return errors.New(NotValidMessage)
	}

	return nil
}

type KnownAResources map[string]int
type KnownTxtResources map[string]string

func fetchTxtResourceByName(name string) (string, bool, error) {
	var txtResources = make(KnownTxtResources)
	txtResources["google.com"] = "it_works"

	result, ok := txtResources[name]

	return result, ok, nil
}

func fetchAResourceByName(name string) (int, bool, error) {
	var aResources = make(KnownAResources)
	/** ip адрес go.dev*/
	aResources["google.com"] = 3639550997
	aResources["www.google.com"] = 3639550997

	result, ok := aResources[name]

	return result, ok, nil
}

func prepareResourceEntryForEntry(question DnsMessageQuestionSectionEntry) (DnsMessageResourceEntry, bool, error) {
	var result = DnsMessageResourceEntry{}
	result.Name = question.QName
	result.Type = question.QType
	result.Class = question.QClass
	result.TTL = 0

	if question.QType == QType_TXT {
		resource, ok, err := fetchTxtResourceByName(result.Name)
		if !ok || err != nil {
			return result, false, err
		}

		result.RdLength = uint16(len(resource) + 1)
		result.RdData = append(result.RdData, uint8(len(resource)))
		result.RdData = append(result.RdData, []byte(resource)...)
	}

	if question.QType == QType_A {
		resource, ok, err := fetchAResourceByName(result.Name)
		if !ok || err != nil {
			return result, false, err
		}

		result.RdLength = uint16(4)
		result.RdData = binary.BigEndian.AppendUint32(result.RdData, uint32(resource))
	}

	return result, true, nil
}
