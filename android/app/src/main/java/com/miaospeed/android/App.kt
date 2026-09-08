package com.miaospeed.android

import android.app.Application

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        AppRuntime.init(this)
        ConfigStore.init(this)
    }
}
