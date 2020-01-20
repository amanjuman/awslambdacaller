package aws_iam

import (
	"encoding/csv"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"os"
	"time"
)

const (
	Active   = "Active"
	Inactive = "Inactive"
)

var svc *iam.IAM

func TimeLeftOfUserAgeExpedited(username string) float64 {
	svc := iam.New(session.New())
	input := &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	}
	result, err := svc.ListAccessKeys(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}
	duration := time.Since(result.AccessKeyMetadata[0].CreateDate.UTC())
	return duration.Minutes()
}

func GetUser(username string) {
	svc := iam.New(session.New())
	getUserInput := &iam.GetUserInput{
		UserName: aws.String(username),
	}

	_, err := svc.GetUser(getUserInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
}

func DisableUsersKey(userName string, accessKeyId string) error {
	_, err := svc.UpdateAccessKey(&iam.UpdateAccessKeyInput{
		UserName:    aws.String(userName),
		Status:      aws.String(Inactive),
		AccessKeyId: aws.String(accessKeyId),
	})

	if err != nil {
		return err
	}

	return nil
}

func ReadCsvFile(filePath string) [][]string {
	file, err := os.Open(filePath)

	if err != nil {
		fmt.Println(err)
	}

	defer file.Close()

	reader := csv.NewReader(file)

	awsdata, err := reader.ReadAll()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return awsdata
}
