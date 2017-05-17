################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../service_provider/ecp.cpp \
../service_provider/ias_ra.cpp \
../service_provider/network_ra.cpp \
../service_provider/service_provider.cpp 

O_SRCS += \
../service_provider/ecp.o \
../service_provider/ias_ra.o \
../service_provider/network_ra.o \
../service_provider/service_provider.o 

OBJS += \
./service_provider/ecp.o \
./service_provider/ias_ra.o \
./service_provider/network_ra.o \
./service_provider/service_provider.o 

CPP_DEPS += \
./service_provider/ecp.d \
./service_provider/ias_ra.d \
./service_provider/network_ra.d \
./service_provider/service_provider.d 


# Each subdirectory must supply rules for building sources it contributes
service_provider/%.o: ../service_provider/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


