import { jwtDecode } from "jwt-decode";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { useCookies } from "react-cookie";

import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Dashboard = () => {
    const [cookie, setCookie, removeCookie] = useCookies(["token"]);
    const [decoded, setDecoded] = useState(cookie["token"] ? jwtDecode(cookie["token"]) : null);

    const navigate = useNavigate();

    const refreshToken = () => {
        try {
            axios.get("http://localhost:8000/token")
            .then((res) => {
                console.log(res);
                const decoded = jwtDecode(res.data.accessToken);

                setCookie("token", res.data.accessToken, {
                    expires: new Date(Date.now() + decoded.exp),
                });
            }).catch((error) => {
                console.log(error);
            });
        } catch (error) {
            console.log(error);
        }
    }

    const logout = () => {
        try {
            axios.delete("http://localhost:8000/logout")
            .then((res) => {
                console.log(res);
                removeCookie("token");
                navigate("/login");
            }).catch((error) => {
                console.log(error);
            });
        } catch (error) {
            console.log(error);
        }
    }

    const verify = () => {
        try {
            axios.post("http://localhost:8000/send", {
                email: decoded.email
            })
            .then((res) => {
                console.log(res);
                toast.success("Silahkan melakukan verifikasi melalui pesan yang dikirimkan pada email anda");
            }).catch((error) => {
                console.log(error);
                toast.error("Gagal mengirim verifikasi email");
            });
        } catch (error) {
            console.log(error);
        }

    }

    useEffect(() => {
        if(!cookie["token"]) {
            navigate("/login");
        } else {
            refreshToken();
        }
    }, [cookie["token"], navigate, refreshToken]);

    return (
        <>
            <ToastContainer />
            <div className="p-5 bg-gray-100 flex flex-row justify-between">
                <a href="#" className="font-medium text-primary-600 hover:underline">Welcome Back</a>
                <a onClick={logout} className="font-medium text-primary-600 hover:underline hover:cursor-pointer">Logout</a>
            </div>
            <div className="m-5 flex flex-col">
                <a className="font-medium text-primary-600">Name: {decoded?.name }</a>
                <a className="font-medium text-primary-600">Email: {decoded?.email}</a>
                <a className="font-medium text-primary-600">Verified: {decoded?.verified ? <a className="font-medium text-green-600">Verified</a> : <a className="font-medium text-red-600">Not verified</a>}</a>
                {!decoded?.verified ? <button onClick={verify} className="w-[20%] my-10 text-black bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center">Email Verification</button> : ""}
            </div>
        </>
    )
}

export default Dashboard;