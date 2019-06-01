################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/avl_tree.cpp \
../src/crypto.cpp \
../src/decrypt_packet.cpp \
../src/main.cpp \
../src/sha1-git.cpp \
../src/vipl_printf.cpp 

OBJS += \
./src/avl_tree.o \
./src/crypto.o \
./src/decrypt_packet.o \
./src/main.o \
./src/sha1-git.o \
./src/vipl_printf.o 

CPP_DEPS += \
./src/avl_tree.d \
./src/crypto.d \
./src/decrypt_packet.d \
./src/main.d \
./src/sha1-git.d \
./src/vipl_printf.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


