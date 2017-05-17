################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../isv_enclave/isv_enclave.cpp 

C_SRCS += \
../isv_enclave/isv_enclave_t.c 

O_SRCS += \
../isv_enclave/isv_enclave.o \
../isv_enclave/isv_enclave_t.o 

OBJS += \
./isv_enclave/isv_enclave.o \
./isv_enclave/isv_enclave_t.o 

CPP_DEPS += \
./isv_enclave/isv_enclave.d 

C_DEPS += \
./isv_enclave/isv_enclave_t.d 


# Each subdirectory must supply rules for building sources it contributes
isv_enclave/%.o: ../isv_enclave/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

isv_enclave/%.o: ../isv_enclave/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


