package com.obfuscator.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * Bootstrap методы для invokedynamic обфускации.
 * Этот класс резолвит вызовы invokedynamic в runtime.
 */
public class InvokeDynamicBootstrap {
    
    /**
     * Bootstrap метод для резолва статических вызовов через invokedynamic
     * 
     * @param lookup MethodHandles.Lookup от вызывающего класса
     * @param name имя метода
     * @param type сигнатура метода
     * @param owner владелец метода (internal name)
     * @param methodName оригинальное имя метода
     * @param methodDesc оригинальная дескриптор метода
     * @return CallSite который резолвит вызов к оригинальному методу
     * @throws Throwable если метод не найден
     */
    public static CallSite bootstrap(MethodHandles.Lookup lookup, 
                                      String name, 
                                      MethodType type,
                                      String owner,
                                      String methodName,
                                      String methodDesc) throws Throwable {
        
        // Находим целевой метод
        Class<?> targetClass = Class.forName(owner.replace('/', '.'));
        MethodHandle handle = lookup.findStatic(targetClass, methodName, MethodType.fromMethodDescriptorString(methodDesc, null));
        
        return new java.lang.invoke.ConstantCallSite(handle);
    }
}
